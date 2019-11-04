#pragma once
#include "PluginInterface.h"
#include "EventsUMInterfaces.h"
#include <map>
#include "picosha2.h"

typedef enum {
	CallbackProcessCreate,
	CallbackProcessExit,
	CallbackFileCreate,
} CALLBACK_ID;

class ProcessContext
{
public:
	ProcessContext(std::string imagePath) { this->imagePath = imagePath; }
	void setAccess(bool access) { this->access = access; }
	std::string getImagePath() { return this->imagePath; }
	bool hasAccess() {	return this->access; }
	bool accessChecked = false;
private:
	
	bool access = false;
	std::string imagePath;
};

class AVCookieShield : public IPlugin
{
public:
	// Inherited via IPlugin
	virtual ~AVCookieShield() override {}
	AV_EVENT_RETURN_STATUS callback(int, void*, void**) override;
	void init(IManager* manager, HMODULE module, IConfig* configManager) override;
	void deinit() override;

	virtual std::string& getName() override;
	virtual HMODULE getModule() override;
	virtual std::string& getDescription() override;
	virtual IConfig* getConfig() override;
private:
	std::string name = std::string("CookieShield");
	std::string description = std::string("Implements proactive chromium cookie DB protection.");
	HMODULE module;
	IConfig* configManager;
	ILogger* logger;

	std::map<int, ProcessContext*> accessMap;
};