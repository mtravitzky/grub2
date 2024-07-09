#include <grub/mm.h>
#include <grub/command.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/misc.h>
#include <grub/net/efi.h>
#include <grub/charset.h>

static grub_guid_t dns4_protocol_guid = GRUB_EFI_DNS4_PROTOCOL_GUID;

static grub_err_t
grub_cmd_efi_list_dns (
    struct grub_command *cmd __attribute__ ((unused)),
    int argc  __attribute__ ((unused)),
    char **args __attribute__ ((unused)))
{
  grub_printf ("Experimental\n");
  grub_efi_handle_t *handles;
  grub_efi_uintn_t num_handles;
  //unsigned i, j, k;

  handles = grub_efi_locate_handle (GRUB_EFI_BY_PROTOCOL, &dns4_protocol_guid,
				    0, &num_handles);

  grub_printf ("Handles found: %lu \n", num_handles);

  if(handles){
    grub_printf("First Handle: %p\n", handles[0]);
  }

  return GRUB_ERR_NONE;
}

grub_command_func_t grub_efi_net_list_dns = grub_cmd_efi_list_dns;
