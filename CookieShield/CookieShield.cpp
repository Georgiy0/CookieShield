#include "pch.h"
#include "CookieShield.h"
#include <Psapi.h>
#include <fstream>

AV_EVENT_RETURN_STATUS AVCookieShield::callback(int callbackId, void* event, void** umMessage)
{
	if (callbackId == CallbackFileCreate)
	{
		IEventFSCreate* eventFileCreate = reinterpret_cast<IEventFSCreate*>(event);
		if (eventFileCreate->getFilePath() == this->configManager->getStringParam("ProtectedFile"))
		{
			int PID = eventFileCreate->getRequestorPID();
			if (this->accessMap.find(PID) == this->accessMap.end())
			{
				return AvEventStatusBlock;
			}
			else
			{
				ProcessContext* processContext = this->accessMap[PID];
				if (processContext->accessChecked)
					return processContext->hasAccess() ? AvEventStatusAllow : AvEventStatusBlock;
				else
				{
					// lazy access check
					this->logger->log("Image path: " + processContext->getImagePath());
					std::ifstream input(processContext->getImagePath(), std::ios::binary);
					if (!input.fail())
					{
						picosha2::hash256_one_by_one hasher;
						hasher.process(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
						hasher.finish();

						std::string hex_str = picosha2::get_hash_hex_string(hasher);
						this->logger->log("HASH: " + hex_str);

						std::list<std::string>* whiteList = this->configManager->getListParam("WhiteList");
						for (std::list<std::string>::iterator it = whiteList->begin(); it != whiteList->end(); it++)
						{
							if (hex_str == (*it))
							{
								processContext->setAccess(true);
								processContext->accessChecked = true;
								this->logger->log("Hit white list entry: " + (*it) + ". GRANT ACCESS.");
								return AvEventStatusAllow;
							}
						}
						delete whiteList;
						processContext->setAccess(false);
						processContext->accessChecked = true;
						return AvEventStatusBlock;
					}
				}
			}
		}
	}
	else if (callbackId == CallbackProcessCreate)
	{
		IEventProcessCreate* eventProcessCreate = reinterpret_cast<IEventProcessCreate*>(event);
		this->logger->log("CallbackProcessCreate");
		int PID = eventProcessCreate->getPID();
		// init context for the new process
		// hash will be computed lazily (when process atempts to access protected file).
		this->accessMap.insert(std::pair<int, ProcessContext*>(
				PID,
				new ProcessContext(eventProcessCreate->getImageFileName())
			));
		this->logger->log("Created ProcessContext for PID " + std::to_string(PID) + " (" + eventProcessCreate->getImageFileName() + ")");
		return AvEventStatusAllow;
	}
	else if (callbackId == CallbackProcessExit)
	{
		IEventProcessExit* eventProcessExit = reinterpret_cast<IEventProcessExit*>(event);
		this->logger->log("CallbackProcessExit");
		int PID = eventProcessExit->getPID();
		if (this->accessMap.find(PID) != this->accessMap.end())
		{
			delete this->accessMap[PID];
			this->accessMap.erase(PID);
		}
	}
	return AvEventStatusAllow;
}

void AVCookieShield::init(IManager* manager, HMODULE module, IConfig* configManager)
{
	this->module = module;
	this->logger = manager->getLogger();

	// parameter settings
	this->configManager = configManager;
	paramMap* paramMap = new std::map<std::string, ConfigParamType>();
	paramMap->insert(paramPair("WhiteList", ListParam)); // list of SHA256 hashed of trusted process images
	paramMap->insert(paramPair("ProtectedFile", StringParam)); // path to the protected file

	this->configManager->setParamMap(paramMap);

	// callbacks settings
	manager->registerCallback(this, CallbackFileCreate, AvFileCreate, 1);
	manager->registerCallback(this, CallbackProcessCreate, AvProcessCreate, 1);
	manager->registerCallback(this, CallbackProcessExit, AvProcessExit, 1);
}

void AVCookieShield::deinit()
{
	delete this->configManager->getParamMap();
	delete this;
}

std::string& AVCookieShield::getName()
{
	return this->name;
}

HMODULE AVCookieShield::getModule()
{
	return this->module;
}

std::string& AVCookieShield::getDescription()
{
	return this->description;
}

IConfig* AVCookieShield::getConfig()
{
	return this->configManager;
}
