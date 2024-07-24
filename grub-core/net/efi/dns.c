#include <grub/mm.h>
#include <grub/command.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/misc.h>
#include <grub/net/efi.h>
#include <grub/charset.h>

static grub_guid_t dns4sb_protocol_guid = GRUB_EFI_DNS4_SERVICE_BINDING_PROTOCOL_GUID;

static grub_err_t
grub_cmd_efi_list_dns (
    struct grub_command *cmd __attribute__ ((unused)),
    int argc  __attribute__ ((unused)),
    char **args __attribute__ ((unused)))
{
  grub_printf ("Experimental\n");
  grub_efi_handle_t *handles;
  grub_efi_uintn_t num_handles;
  grub_efi_device_path_t *dp;
  grub_efi_acpi_device_path_t *acpi;
  num_handles = 0;

  handles = grub_efi_locate_handle (GRUB_EFI_BY_PROTOCOL, &dns4sb_protocol_guid,
				    0, &num_handles);

  if(! handles)
  {
      grub_printf ("Handles pointer NULL\n");
      return GRUB_ERR_UNKNOWN_DEVICE;
  }
  grub_printf ("\nHandles found: %lu \n"
               "First handle address: %p\n", num_handles, handles[0]);

  dp = grub_efi_get_device_path(handles[0]);
  grub_free(handles);

  if(! dp)
  {
      grub_printf ("Device Path pointer NULL\n");
      return GRUB_ERR_UNKNOWN_DEVICE;
  }

  dp = grub_efi_find_last_device_path (dp);

  grub_printf ("\nDevice type: %d \n"
               "Device sub-type: %d\n"
               "Device path length: %d", dp->type, dp->subtype, dp->length);

  if (dp->type != GRUB_EFI_ACPI_DEVICE_PATH_TYPE || dp->subtype != GRUB_EFI_ACPI_DEVICE_PATH_SUBTYPE)
  {
      grub_printf ("Wrong device type\n");
      return GRUB_ERR_UNKNOWN_DEVICE;
  }

  acpi = (grub_efi_acpi_device_path_t *) dp;

  grub_printf ("\nDevice HID: %8x\n"
               "Device UID: %8x\n", acpi->hid, acpi->uid);

  return GRUB_ERR_NONE;
}

grub_command_func_t grub_efi_net_list_dns = grub_cmd_efi_list_dns;
