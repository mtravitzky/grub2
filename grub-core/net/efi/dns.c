#include <grub/mm.h>
#include <grub/command.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/misc.h>
#include <grub/net/efi.h>
#include <grub/charset.h>

static grub_err_t
grub_cmd_efi_list_dns (
    struct grub_command *cmd __attribute__ ((unused)),
    int argc  __attribute__ ((unused)),
    char **args __attribute__ ((unused)))
{
  grub_printf ("Unimplemented\n");
  return GRUB_ERR_NONE;
}

grub_command_func_t grub_efi_net_list_dns = grub_cmd_efi_list_dns;
