import logging
import aiohttp
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD, CONF_VERIFY_SSL
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

DATA_SCHEMA = vol.Schema({
    vol.Required(CONF_HOST): str,
    vol.Required(CONF_USERNAME): str,
    vol.Required(CONF_PASSWORD): str,
    vol.Optional(CONF_VERIFY_SSL, default=True): bool,
    vol.Optional("enable_new_entities", default=False): bool 
})
class CiscoWLConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Cisco 9800 WLC."""
    VERSION = 1

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}

        if user_input is not None:
            session = async_get_clientsession(self.hass, verify_ssl=not user_input[CONF_VERIFY_SSL])
            url = f"https://{user_input[CONF_HOST]}/restconf/data"
            auth = aiohttp.BasicAuth(user_input[CONF_USERNAME], user_input[CONF_PASSWORD])
            headers = {"Accept": "application/yang-data+json"}

            try:
                async with session.get(url, auth=auth, headers=headers) as response:
                    _LOGGER.debug("WLC API Response Code: %s", response.status)

                    if response.status == 401:
                        errors["base"] = "invalid_auth"
                    elif response.status != 200:
                        errors["base"] = "cannot_connect"
                    else:
                        return self.async_create_entry(
                            title=user_input[CONF_HOST],
                            data=user_input,
                            options={"enable_new_entities": user_input.get("enable_new_entities", False)}  # Ensures default if key missing
                        )

            except aiohttp.ClientConnectorCertificateError:
                _LOGGER.error("SSL Certificate Verification Failed. Try enabling 'Ignore Self-Signed SSL'.")
                errors["base"] = "ssl_error"
            except aiohttp.ClientError as e:
                _LOGGER.error("Client error connecting to Cisco 9800 WLC: %s", e)
                errors["base"] = "cannot_connect"
            except Exception as e:
                _LOGGER.error("Unexpected error: %s", e)
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user",
            data_schema=DATA_SCHEMA,
            errors=errors,
            description_placeholders={
                "setup_hint": "Make sure RESTCONF is enabled on your WLC before proceeding.",
                "enable_new_entities_label": "Disable new Entities"
            },
        )

    async def async_step_options(self, user_input=None):
        """Handle options configuration."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(
            step_id="options",
            data_schema=vol.Schema({
                vol.Optional("enable_new_entities", default=self.options.get("enable_new_entities", False)): bool
            }),
            description_placeholders={
                "enable_new_entities_label": "Disable new Entities"  # Custom label text for the user
            },
    )