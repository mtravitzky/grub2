/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2014 Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/err.h>
#include <grub/mm.h>
#include <grub/types.h>
#include <grub/cpu/linux.h>
#include <grub/efi/efi.h>
#include <grub/efi/pe32.h>
#include <grub/efi/linux.h>
#include <grub/kernel.h>
#include <grub/loader.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

typedef void (*handover_func) (void *, grub_efi_system_table_t *, void *);

grub_err_t
grub_efi_linux_boot (void *kernel_addr, grub_off_t handover_offset,
		     void *kernel_params)
{
  grub_efi_loaded_image_t *loaded_image = NULL;
  handover_func hf;
  int offset = 0;

#ifdef __x86_64__
  grub_efi_simple_text_output_interface_t *o;
  o = grub_efi_system_table->con_out;
  offset = 512;
#endif

  /*
   * Since the EFI loader is not calling the LoadImage() and StartImage()
   * services for loading the kernel and booting respectively, it has to
   * set the Loaded Image base address.
   */
  loaded_image = grub_efi_get_loaded_image (grub_efi_image_handle);
  if (loaded_image)
    loaded_image->image_base = kernel_addr;
  else
    grub_dprintf ("linux", "Loaded Image base address could not be set\n");

  grub_dprintf ("linux", "kernel_addr: %p handover_offset: %p params: %p\n",
		kernel_addr, (void *)(grub_efi_uintn_t)handover_offset, kernel_params);
  hf = (handover_func)((char *)kernel_addr + handover_offset + offset);
#ifdef __x86_64__
  grub_machine_fini (GRUB_LOADER_FLAG_NORETURN);
#endif
  hf (grub_efi_image_handle, grub_efi_system_table, kernel_params);

#ifdef __x86_64__
  efi_call_2 (o->output_string, o, L"cannot boot linux kernel via efi handover\r\n"
	      L"rebooting in 5 seconds... *\r\n");
  efi_call_1 (grub_efi_system_table->boot_services->stall, 5000000);
  efi_call_4 (grub_efi_system_table->runtime_services->reset_system,
	      GRUB_EFI_RESET_COLD, GRUB_EFI_SUCCESS, 0, NULL);
  for (;;) ;
#else
  return GRUB_ERR_BUG;
#endif
}

#pragma GCC diagnostic pop
