/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2022 Microsoft Corporation
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

#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/protector.h>
#include <grub/time.h>
#include <grub/tpm2/buffer.h>
#include <grub/tpm2/internal/args.h>
#include <grub/tpm2/mu.h>
#include <grub/tpm2/tpm2.h>
#include <grub/efi/efi.h>

GRUB_MOD_LICENSE ("GPLv3+");

typedef enum grub_tpm2_protector_mode
{
  GRUB_TPM2_PROTECTOR_MODE_UNSET,
  GRUB_TPM2_PROTECTOR_MODE_SRK,
  GRUB_TPM2_PROTECTOR_MODE_NV,
  GRUB_TPM2_PROTECTOR_MODE_AUTHPOL
} grub_tpm2_protector_mode_t;

struct grub_tpm2_protector_context
{
  grub_tpm2_protector_mode_t mode;
  grub_uint8_t pcrs[TPM_MAX_PCRS];
  grub_uint8_t pcr_count;
  TPML_PCR_SELECTION pcr_list;
  TPM_ALG_ID asymmetric;
  TPM_ALG_ID bank;
  const char *keyfile;
  const char *pkfile;
  const char *sigfile;
  TPM_HANDLE srk;
  TPM_HANDLE nv;
  const char *efivar;
};

static const struct grub_arg_option grub_tpm2_protector_init_cmd_options[] =
  {
    /* Options for all modes */
    {
      .longarg  = "mode",
      .shortarg = 'm',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("Unseal key using SRK ('srk') (default), retrieve it from an NV "
           "Index ('nv'), or unseal key with a authorized policy ('authpol')."),
    },
    {
      .longarg  = "pcrs",
      .shortarg = 'p',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("Comma-separated list of PCRs used to authorize key release "
           "(e.g., '7,11', default is 7."),
    },
    {
      .longarg  = "bank",
      .shortarg = 'b',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("Bank of PCRs used to authorize key release: "
           "SHA1, SHA256 (default), or SHA384."),
    },
    /* SRK-mode and Authorized Policy-mode options */
    {
      .longarg  = "keyfile",
      .shortarg = 'k',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("Required in SRK and Authorized Policy mode, path to the sealed "
           "key file to unseal using the TPM "
           "(e.g., (hd0,gpt1)/boot/grub2/sealed_key)."),
    },
    {
      .longarg  = "srk",
      .shortarg = 's',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("In SRK and Authorized Policy mode, the SRK handle if the SRK is "
           "persistent (default is 0x81000001)."),
    },
    {
      .longarg  = "asymmetric",
      .shortarg = 'a',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("In SRK and Authorized Policy mode, the type of SRK: RSA "
           "(default) or ECC."),
    },
    /* NV Index-mode options */
    {
      .longarg  = "nvindex",
      .shortarg = 'n',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("Required in NV Index mode, the NV handle to read which must "
           "readily exist on the TPM and which contains the key."),
    },
    /* When publishing the unsealed key to a UEFI variable */
    {
      .longarg  = "efivar",
      .shortarg = 'E',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("Publish the unsealed key to the indicated UEFI variable."),
    },
    /* Authorized Policy-mode options */
    {
      .longarg  = "pkfile",
      .shortarg = 'P',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("Public key file to verify the PCR policy signature"
           "(e.g., (hd0,gpt1)/boot/grub2/pub.key)"),
    },
    {
      .longarg  = "sigfile",
      .shortarg = 'S',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("PCR policy signature file (e.g., (hd0,gpt1)/boot/grub2/pol.sig)"),
    },
    /* End of list */
    {0, 0, 0, 0, 0, 0}
  };

static grub_extcmd_t grub_tpm2_protector_init_cmd;
static grub_extcmd_t grub_tpm2_protector_clear_cmd;
static struct grub_tpm2_protector_context grub_tpm2_protector_ctx = { 0 };

static grub_err_t
grub_tpm2_protector_read_file (const char *filepath, void **buffer,
                               grub_size_t *buffer_size)
{
  grub_file_t file;
  grub_off_t file_size;
  void *file_buffer;
  grub_off_t file_read;

  /* Using GRUB_FILE_TYPE_SIGNATURE ensures we do not hash the keyfile into PCR9
   * otherwise we'll never be able to predict the value of PCR9 at unseal time */
  file = grub_file_open (filepath, GRUB_FILE_TYPE_SIGNATURE);
  if (!file)
    {
      grub_dprintf ("tpm2", "Could not open file: %s\n", filepath);
      /* grub_file_open sets grub_errno on error, and if we do no unset it,
       * future calls to grub_file_open will fail (and so will anybody up the
       * stack who checks the value, if any). */
      grub_errno = GRUB_ERR_NONE;
      return GRUB_ERR_FILE_NOT_FOUND;
    }

  file_size = grub_file_size (file);
  if (!file_size)
    {
      grub_dprintf ("tpm2", "Could not read file size: %s\n", filepath);
      grub_file_close (file);
      return GRUB_ERR_OUT_OF_RANGE;
    }

  file_buffer = grub_malloc (file_size);
  if (!file_buffer)
    {
      grub_dprintf ("tpm2", "Could not allocate buffer: %s\n", filepath);
      grub_file_close (file);
      return GRUB_ERR_OUT_OF_MEMORY;
    }

  file_read = grub_file_read (file, file_buffer, file_size);
  if (file_read != file_size)
    {
      grub_dprintf ("tpm2", "Could not retrieve file contents: %s\n", filepath);
      grub_free (file_buffer);
      grub_file_close (file);
      return GRUB_ERR_FILE_READ_ERROR;
    }

  grub_file_close (file);

  *buffer = file_buffer;
  *buffer_size = file_size;

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_unmarshal_pkfile (void *pub_key,
                                      grub_size_t pub_key_size,
                                      TPM2B_PUBLIC *pk)
{
  struct grub_tpm2_buffer buf;

  grub_tpm2_buffer_init (&buf);
  if (pub_key_size > buf.cap)
    {
      grub_dprintf ("tpm2", "Public key file is larger than decode buffer "
                            "(%" PRIuGRUB_SIZE " vs %" PRIuGRUB_SIZE " bytes).\n", pub_key_size, buf.cap);
      return GRUB_ERR_BAD_ARGUMENT;
    }

  grub_memcpy (buf.data, pub_key, pub_key_size);
  buf.size = pub_key_size;

  grub_tpm2_mu_TPM2B_PUBLIC_Unmarshal (&buf, pk);

  if (buf.error)
    {
      grub_dprintf ("tpm2", "Could not unmarshal public key file, it is likely "
                            "malformed.\n");
      return GRUB_ERR_BAD_ARGUMENT;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_unmarshal_sigfile (void *sig,
                                       grub_size_t sig_size,
                                       TPMT_SIGNATURE *signature)
{
  struct grub_tpm2_buffer buf;

  grub_tpm2_buffer_init (&buf);
  if (sig_size > buf.cap)
    {
      grub_dprintf ("tpm2", "Signed PCR policy file is larger than decode buffer "
                            "(%" PRIuGRUB_SIZE " vs %" PRIuGRUB_SIZE " bytes).\n", sig_size, buf.cap);
      return GRUB_ERR_BAD_ARGUMENT;
    }

  grub_memcpy (buf.data, sig, sig_size);
  buf.size = sig_size;

  grub_tpm2_mu_TPMT_SIGNATURE_Unmarshal (&buf, signature);

  if (buf.error)
    {
      grub_dprintf ("tpm2", "Could not unmarshal public key file, it is likely "
                            "malformed.\n");
      return GRUB_ERR_BAD_ARGUMENT;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_unmarshal_keyfile (void *sealed_key,
                                       grub_size_t sealed_key_size,
                                       TPM2_SEALED_KEY *sk)
{
  struct grub_tpm2_buffer buf;

  grub_tpm2_buffer_init (&buf);
  if (sealed_key_size > buf.cap)
    {
      grub_dprintf ("tpm2", "Sealed key file is larger than decode buffer "
                            "(%" PRIuGRUB_SIZE " vs %" PRIuGRUB_SIZE " bytes).\n", sealed_key_size, buf.cap);
      return GRUB_ERR_BAD_ARGUMENT;
    }

  grub_memcpy (buf.data, sealed_key, sealed_key_size);
  buf.size = sealed_key_size;

  grub_tpm2_mu_TPM2B_PUBLIC_Unmarshal (&buf, &sk->public);
  grub_tpm2_mu_TPM2B_Unmarshal (&buf, (TPM2B *)&sk->private);

  if (buf.error)
    {
      grub_dprintf ("tpm2", "Could not unmarshal sealed key file, it is likely "
                            "malformed.\n");
      return GRUB_ERR_BAD_ARGUMENT;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_srk_get (const struct grub_tpm2_protector_context *ctx,
                             TPM_HANDLE *srk)
{
  TPM_RC rc;
  TPM2B_PUBLIC public;
  TPMS_AUTH_COMMAND authCommand = { 0 };
  TPM2B_SENSITIVE_CREATE inSensitive = { 0 };
  TPM2B_PUBLIC inPublic = { 0 };
  TPM2B_DATA outsideInfo = { 0 };
  TPML_PCR_SELECTION creationPcr = { 0 };
  TPM2B_PUBLIC outPublic = { 0 };
  TPM2B_CREATION_DATA creationData = { 0 };
  TPM2B_DIGEST creationHash = { 0 };
  TPMT_TK_CREATION creationTicket = { 0 };
  TPM2B_NAME srkName = { 0 };
  TPM_HANDLE srkHandle;

  /* Find SRK */
  rc = TPM2_ReadPublic (ctx->srk, NULL, &public);
  if (rc == TPM_RC_SUCCESS)
    {
      *srk = ctx->srk;
      return GRUB_ERR_NONE;
    }

  /* The handle exists but its public area could not be read. */
  if ((rc & ~TPM_RC_N_MASK) != TPM_RC_HANDLE)
    {
      grub_dprintf ("tpm2", "The SRK handle (0x%x) exists on the TPM but its "
                            "public area could not be read (TPM2_ReadPublic "
                            "failed with TSS/TPM error %u).\n", ctx->srk, rc);
      return GRUB_ERR_BAD_DEVICE;
    }

  /* Create SRK */
  authCommand.sessionHandle = TPM_RS_PW;
  inPublic.publicArea.type = ctx->asymmetric;
  inPublic.publicArea.nameAlg  = TPM_ALG_SHA256;
  inPublic.publicArea.objectAttributes.restricted = 1;
  inPublic.publicArea.objectAttributes.userWithAuth = 1;
  inPublic.publicArea.objectAttributes.decrypt = 1;
  inPublic.publicArea.objectAttributes.fixedTPM = 1;
  inPublic.publicArea.objectAttributes.fixedParent = 1;
  inPublic.publicArea.objectAttributes.sensitiveDataOrigin = 1;
  inPublic.publicArea.objectAttributes.noDA = 1;

  if (ctx->asymmetric == TPM_ALG_RSA)
    {
      inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
      inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
      inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
      inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
      inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
      inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    }
  else if (ctx->asymmetric == TPM_ALG_ECC)
    {
      inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
      inPublic.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
      inPublic.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
      inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
      inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
      inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    }
  else
    return GRUB_ERR_BAD_ARGUMENT;

  rc = TPM2_CreatePrimary (TPM_RH_OWNER, &authCommand, &inSensitive, &inPublic,
                           &outsideInfo, &creationPcr, &srkHandle, &outPublic,
                           &creationData, &creationHash, &creationTicket,
                           &srkName, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      grub_dprintf ("tpm2", "Could not create SRK (TPM2_CreatePrimary failed "
                            "with TSS/TPM error %u).\n", rc);
      return GRUB_ERR_BAD_DEVICE;
    }

  *srk = srkHandle;

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_publish_key (grub_uint8_t *key, grub_size_t key_size,
				 const char *var_name)
{
  grub_efi_guid_t vendor_guid = { 0x58aca851, 0x8af7, 0x4738, { 0xa5, 0x42, 0x26, 0x6e, 0x21, 0xf5, 0xca, 0xd9 }};
  grub_uint8_t *tmp_key;
  grub_err_t err;

  /* It appears that EFI's set_var function overwrites the key. */
  tmp_key = grub_malloc (key_size);
  if (!tmp_key)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("No memory left to allocate temporary key buffer"));
      return GRUB_ERR_OUT_OF_MEMORY;
    }

  grub_memcpy(tmp_key, key, key_size);

  err = grub_efi_set_variable_with_attributes(var_name, &vendor_guid,
					      GRUB_EFI_VARIABLE_BOOTSERVICE_ACCESS | GRUB_EFI_VARIABLE_RUNTIME_ACCESS,
					      tmp_key, key_size);
  if (err)
    grub_error (err, N_("Failed to export LUKS key as EFI variable %s"), var_name);

  grub_free (tmp_key);
  return err;
}

static grub_err_t
grub_tpm2_protector_srk_recover (const struct grub_tpm2_protector_context *ctx,
                                 grub_uint8_t **key, grub_size_t *key_size)
{
  TPM_RC rc;
  TPM2_SEALED_KEY sealed_key;
  void *sealed_key_bytes;
  grub_size_t sealed_key_size;
  TPM_HANDLE srk_handle;
  TPM2B_NONCE nonceCaller = { 0 };
  TPMT_SYM_DEF symmetric = { 0 };
  TPMI_SH_AUTH_SESSION session;
  TPMS_AUTH_COMMAND authCmd = { 0 };
  TPM_HANDLE sealed_key_handle;
  TPM2B_NAME name;
  TPMS_AUTH_RESPONSE authResponse;
  TPM2B_SENSITIVE_DATA data;
  grub_uint8_t *key_out;
  grub_err_t err;

  /* Retrieve Sealed Key */
  err = grub_tpm2_protector_read_file (ctx->keyfile, &sealed_key_bytes,
                                       &sealed_key_size);
  if (err)
    return grub_error (err, N_("Failed to read key file %s"), ctx->keyfile);

  err = grub_tpm2_protector_unmarshal_keyfile (sealed_key_bytes,
                                               sealed_key_size,
                                               &sealed_key);
  if (err)
    {
      grub_error (err, N_("Failed to unmarshal key, ensure the key file is in "
                          "TPM wire format"));
      goto exit1;
    }

  /* Get SRK */
  err = grub_tpm2_protector_srk_get (ctx, &srk_handle);
  if (err)
    {
      grub_error (err, N_("Failed to retrieve the SRK"));
      goto exit1;
    }

  err = GRUB_ERR_BAD_DEVICE;

  /* Start Auth Session */
  nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
  symmetric.algorithm = TPM_ALG_NULL;

  rc = TPM2_StartAuthSession (TPM_RH_NULL, TPM_RH_NULL, NULL, &nonceCaller, NULL,
                              TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256,
                              &session, NULL, NULL);
  if (rc)
    {
      grub_error (err, N_("Failed to start auth session (TPM2_StartAuthSession "
                          "failed with TSS/TPM error %u)"), rc);
      goto exit2;
    }

  /* Policy PCR */
  rc = TPM2_PolicyPCR (session, NULL, NULL, &ctx->pcr_list, NULL);
  if (rc)
    {
      grub_error (err, N_("Failed to submit PCR policy (TPM2_PolicyPCR failed "
                          "with TSS/TPM error %u)"), rc);
      goto exit3;
    }

  /* Load Sealed Key */
  authCmd.sessionHandle = TPM_RS_PW;
  rc = TPM2_Load (srk_handle, &authCmd, &sealed_key.private, &sealed_key.public,
                  &sealed_key_handle, &name, &authResponse);
  if (rc)
    {
      grub_error (err, N_("Failed to load sealed key (TPM2_Load failed with "
                          "TSS/TPM error %u)"), rc);
      goto exit3;
    }

  /* Unseal Sealed Key */
  authCmd.sessionHandle = session;
  grub_memset (&authResponse, 0, sizeof (authResponse));

  rc = TPM2_Unseal (sealed_key_handle, &authCmd, &data, &authResponse);
  if (rc)
    {
      grub_error (err, N_("Failed to unseal sealed key (TPM2_Unseal failed "
                          "with TSS/TPM error %u)"), rc);
      grub_millisleep(500);
      goto exit4;
    }

  /* Epilogue */
  key_out = grub_malloc (data.size);
  if (!key_out)
    {
      err = GRUB_ERR_OUT_OF_MEMORY;
      grub_error (err, N_("No memory left to allocate unlock key buffer"));
      goto exit4;
    }

  grub_printf("TPM2: unsealed %u bytes of key material\n", data.size);

  if (ctx->efivar)
    {
      rc = grub_tpm2_protector_publish_key (data.buffer, data.size, ctx->efivar);
      if (rc)
	goto exit4;
    }

  grub_memcpy (key_out, data.buffer, data.size);

  *key = key_out;
  *key_size = data.size;

  err = GRUB_ERR_NONE;

exit4:
  TPM2_FlushContext (sealed_key_handle);

exit3:
  TPM2_FlushContext (session);

exit2:
  TPM2_FlushContext (srk_handle);

exit1:
  grub_free (sealed_key_bytes);
  return err;
}

static grub_err_t
grub_tpm2_protector_nv_recover (const struct grub_tpm2_protector_context *ctx,
                                grub_uint8_t **key, grub_size_t *key_size)
{
  (void)ctx;
  (void)key;
  (void)key_size;

  return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                     N_("NV Index mode is not implemented yet"));
}

static grub_err_t
get_pcr_digest (const struct grub_tpm2_protector_context *ctx,
                TPM2B_DIGEST *pcr_digest)
{
  TPM_RC rc;
  TPML_PCR_SELECTION pcr_list_out = { 0 };
  TPML_DIGEST pcr_values = { 0 };
  grub_size_t pcr_digest_len;
  TPM2B_AUTH auth = { 0 };
  TPMI_DH_OBJECT sequence = 0;
  TPMS_AUTH_COMMAND authCmd;
  grub_uint8_t i;
  TPM2B_DIGEST result_digest;
  grub_err_t err = GRUB_ERR_INVALID_COMMAND;

  if (!pcr_digest)
    return GRUB_ERR_BAD_ARGUMENT;

  /* PCR Read */
  rc = TPM2_PCR_Read (NULL, &ctx->pcr_list, NULL, &pcr_list_out, &pcr_values, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      err = GRUB_ERR_BAD_DEVICE;
      return grub_error (err, N_("Failed to read PCRs (TPM error: 0x%x)."), rc);
    }

  if ((pcr_list_out.count != ctx->pcr_list.count) ||
       (ctx->pcr_list.pcrSelections[0].sizeOfSelect !=
        pcr_list_out.pcrSelections[0].sizeOfSelect))
    {
      err = GRUB_ERR_BAD_DEVICE;
      return grub_error (err, N_("Could not read all the specified PCRs."));
    }

  /* Check the hash algorithm */
  switch (ctx->bank)
    {
    case TPM_ALG_SHA1:
      pcr_digest_len = TPM_SHA1_DIGEST_SIZE;
      break;
    case TPM_ALG_SHA256:
      pcr_digest_len = TPM_SHA256_DIGEST_SIZE;
      break;
    case TPM_ALG_SHA384:
      pcr_digest_len = TPM_SHA384_DIGEST_SIZE;
      break;
    case TPM_ALG_SHA512:
      pcr_digest_len = TPM_SHA512_DIGEST_SIZE;
      break;
    default:
      return GRUB_ERR_BAD_ARGUMENT;
    }

  /* Start the hash sequence with an empty password (auth) */
  rc = TPM2_HashSequenceStart (NULL, &auth, ctx->bank, &sequence, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      err = GRUB_ERR_BAD_DEVICE;
      return grub_error (err,
                         N_("Failed to start hash sequence (TPM error: 0x%x)."),
                         rc);
    }

  /* Set up the password session with an empty password for TPM2_SequenceUpdate */
  /* and TPM2_SequenceComplete */
  grub_memset (&authCmd, 0, sizeof (TPMS_AUTH_COMMAND));
  authCmd.sessionHandle = TPM_RS_PW;

  for (i = 0; i < ctx->pcr_count; i++)
    {
      if (pcr_values.digests[i].size != pcr_digest_len)
        {
          err = GRUB_ERR_BAD_DEVICE;
          grub_error (err,
                      N_("Bad PCR value size: expected %" PRIuGRUB_SIZE " bytes but got %u bytes.\n"),
                      pcr_digest_len, pcr_values.digests[i].size);
          goto error;
        }

      rc = TPM2_SequenceUpdate (sequence, &authCmd,
                                (TPM2B_MAX_BUFFER *)&pcr_values.digests[i],
                                NULL);
      if (rc != TPM_RC_SUCCESS)
        {
          err = GRUB_ERR_BAD_DEVICE;
          grub_error (err,
                      N_("Failed to update hash sequence (TPM error: 0x%x)."),
                      rc);
          goto error;
        }
    }

  rc = TPM2_SequenceComplete (sequence, &authCmd, NULL, TPM_RH_NULL,
                              &result_digest, NULL, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      err = GRUB_ERR_BAD_DEVICE;
      grub_error (err,
                  N_("Failed to complete hash sequence (TPM error: 0x%x)."),
                  rc);
      goto error;
    }

  *pcr_digest = result_digest;
  sequence = 0;
  err = GRUB_ERR_NONE;

error:

  /* End the sequence if necessary */
  if (sequence != 0)
    {
      grub_memset (&authCmd, 0, sizeof (TPMS_AUTH_COMMAND));
      authCmd.sessionHandle = TPM_RS_PW;
      TPM2_SequenceComplete (sequence, &authCmd, NULL, TPM_RH_NULL,
                             &result_digest, NULL, NULL);
    }

  return err;
}

static grub_err_t
grub_tpm2_protector_authpol_digest (const struct grub_tpm2_protector_context *ctx,
                                    TPM2B_DIGEST *digest)
{
  TPM_RC rc;
  TPM2B_DIGEST pcr_digest;
  TPM2B_NONCE nonce = { 0 };
  TPMT_SYM_DEF symmetric = { 0 };
  TPMI_SH_AUTH_SESSION session = 0;
  TPM2B_DIGEST policy_digest = { 0 };
  grub_err_t err;

  err = get_pcr_digest (ctx, &pcr_digest);
  if (err != GRUB_ERR_NONE)
    return err;

  /* Start Trial Session to calculate the policy digest */
  nonce.size = TPM_SHA256_DIGEST_SIZE;
  symmetric.algorithm = TPM_ALG_NULL;

  rc = TPM2_StartAuthSession (TPM_RH_NULL, TPM_RH_NULL, NULL, &nonce, NULL,
                              TPM_SE_TRIAL, &symmetric, TPM_ALG_SHA256,
                              &session, NULL, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      err = GRUB_ERR_BAD_DEVICE;
      grub_error (err,
                  N_("Failed to start trial policy session (TPM error: 0x%x)."),
                  rc);
      goto error;
    }

  /* PCR Policy */
  rc = TPM2_PolicyPCR (session, NULL, &pcr_digest, &ctx->pcr_list, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      err = GRUB_ERR_BAD_DEVICE;
      grub_error (err, _("Failed to submit PCR policy (TPM error: 0x%x)."),
                  rc);
      goto error;
    }

  /* Retrieve Policy Digest */
  rc = TPM2_PolicyGetDigest (session, NULL, &policy_digest, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      err = GRUB_ERR_BAD_DEVICE;
      grub_error (err, _("Failed to get policy digest (TPM error: 0x%x)."),
                  rc);
      goto error;
    }

  /* Epilogue */
  *digest = policy_digest;
  err = GRUB_ERR_NONE;

error:
  TPM2_FlushContext (session);

  return err;
}

static grub_err_t
grub_tpm2_protector_authpol_recover (const struct grub_tpm2_protector_context *ctx,
                                     grub_uint8_t **key, grub_size_t *key_size)
{
  TPM_RC rc;
  TPM2B_DIGEST pcr_policy;
  TPM2B_DIGEST pcr_policy_hash;
  TPM2B_PUBLIC pub_key;
  void *pub_key_bytes = NULL;
  grub_size_t pub_key_size;
  TPM2B_NAME pubname;
  TPMT_SIGNATURE signature;
  void *sig_bytes = NULL;
  grub_size_t sig_size;
  TPM2_SEALED_KEY sealed_key;
  void *sealed_key_bytes = NULL;
  grub_size_t sealed_key_size;
  TPM_HANDLE pubkey_handle = 0;
  TPM_HANDLE primary_handle = 0;
  TPM_HANDLE sealed_key_handle = 0;
  TPMT_SYM_DEF symmetric = { 0 };
  TPM2B_NONCE nonceCaller = { 0 };
  TPMI_SH_AUTH_SESSION session;
  TPM2B_SENSITIVE_DATA data;
  TPMS_AUTH_COMMAND authCmd = { 0 };
  TPMT_TK_VERIFIED verification_ticket;
  grub_uint8_t *key_out;
  grub_err_t err;

  /* Retrieve Public Key */
  err = grub_tpm2_protector_read_file (ctx->pkfile, &pub_key_bytes,
                                       &pub_key_size);
  if (err)
    return grub_error (err, N_("Failed to read public key file %s"),
                       ctx->pkfile);

  err = grub_tpm2_protector_unmarshal_pkfile (pub_key_bytes,
                                              pub_key_size,
                                              &pub_key);
  if (err)
    {
      grub_error (err, N_("Failed to unmarshal public key, ensure the public "
                          "key file is in TPM wire format"));
      goto exit1;
    }

  /* Retrieve Signed PCR Policy */
  err = grub_tpm2_protector_read_file (ctx->sigfile, &sig_bytes,
                                       &sig_size);
  if (err)
    {
      grub_error (err, N_("Failed to read signed pcr policy file %s"),
                  ctx->sigfile);
      goto exit1;
    }

  err = grub_tpm2_protector_unmarshal_sigfile (sig_bytes,
                                               sig_size,
                                               &signature);
  if (err)
    {
      grub_error (err, N_("Failed to unmarshal signed PCR policy, ensure the signed "
                          "PCR policy file is in TPM wire format"));
      goto exit1;
    }

  /* Retrieve Sealed Key */
  err = grub_tpm2_protector_read_file (ctx->keyfile, &sealed_key_bytes,
                                       &sealed_key_size);
  if (err)
    {
      grub_error (err, N_("Failed to read key file %s"), ctx->keyfile);
      goto exit1;
    }

  err = grub_tpm2_protector_unmarshal_keyfile (sealed_key_bytes,
                                               sealed_key_size,
                                               &sealed_key);
  if (err)
    {
      grub_error (err, N_("Failed to unmarshal key, ensure the key file is in "
                          "TPM wire format"));
      goto exit1;
    }

  /* Reproduce the policy signed by the public key */
  err = grub_tpm2_protector_authpol_digest (ctx, &pcr_policy);
  if (err)
    {
      grub_error (err, N_("Failed to get the policy digest"));
      goto exit1;
    }

  /* Load the public key */
  rc = TPM2_LoadExternal (NULL, NULL, &pub_key, TPM_RH_OWNER,
                          &pubkey_handle, &pubname, NULL);
  if (rc)
    {
      err = GRUB_ERR_BAD_DEVICE;
      grub_error (err, N_("Failed to load public key (TPM2_LoadExternal failed "
                          "with TSS/TPM error %u)"), rc);
      goto exit1;
    }

  /* Calculate the digest of the polcy for VerifySignature */
  rc = TPM2_Hash (NULL, (TPM2B_MAX_BUFFER *)&pcr_policy, TPM_ALG_SHA256,
                  TPM_RH_NULL, &pcr_policy_hash, NULL, NULL);
  if (rc)
    {
      err = GRUB_ERR_BAD_DEVICE;
      grub_error (err, N_("Failed to create PCR policy hash (TPM2_Hash failed "
                          "with TSS/TPM error %u)"), rc);
      goto exit2;
    }

  /* Verify the signature against the public key and the reproduced policy digest */
  rc = TPM2_VerifySignature (pubkey_handle, NULL, &pcr_policy_hash, &signature,
                             &verification_ticket, NULL);
  if (rc)
    {
      err = GRUB_ERR_BAD_DEVICE;
      grub_error (err, N_("Failed to verify signature (TPM2_VerifySignature "
                          "failed with TSS/TPM error %u)"), rc);
      goto exit2;
    }

  /* Get the handle of the primary storage key */
  err = grub_tpm2_protector_srk_get (ctx, &primary_handle);
  if (err)
    {
      grub_error (err, N_("Failed to create primary"));
      goto exit2;
    }

  /* Load Sealed Key */
  /*   Use the password session with an empty password */
  grub_memset (&authCmd, 0, sizeof (authCmd));
  authCmd.sessionHandle = TPM_RS_PW;
  /*   Load the sealed object into TPM */
  rc = TPM2_Load (primary_handle, &authCmd, &sealed_key.private, &sealed_key.public,
                  &sealed_key_handle, NULL, NULL);
  if (rc)
    {
      grub_error (err, N_("Failed to load sealed key (TPM2_Load failed with "
                          "TSS/TPM error %u)"), rc);
      goto exit3;
    }

  /* Start a policy session to authorize the signed policy */
  symmetric.algorithm = TPM_ALG_AES;
  symmetric.keyBits.aes = 128;
  symmetric.mode.aes = TPM_ALG_CFB;
  nonceCaller.size = TPM_SHA256_DIGEST_SIZE;

  rc = TPM2_StartAuthSession (TPM_RH_NULL, TPM_RH_NULL, NULL, &nonceCaller, NULL,
                              TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256,
                              &session, NULL, NULL);
  if (rc)
    {
      grub_error (err, N_("Failed to start auth session (TPM2_StartAuthSession "
                          "failed with TSS/TPM error %u)"), rc);
      goto exit4;
    }

  /* Send the PolicyPCR command to generate the policy digest based on the */
  /* current PCR values */
  rc = TPM2_PolicyPCR (session, NULL, NULL, &ctx->pcr_list, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      err = GRUB_ERR_BAD_DEVICE;
      grub_error (err, N_("Failed to submit PCR policy (TPM2_PolicyPCR failed "
                          "with TSS/TPM error: 0x%u).\n"), rc);
      goto exit5;
    }

  /* Authorize the signed policy with the public key and the verification ticket */
  rc = TPM2_PolicyAuthorize (session, NULL, &pcr_policy, NULL, &pubname,
                             &verification_ticket, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      err = GRUB_ERR_BAD_DEVICE;
      grub_error (err, N_("Failed to authorize PCR policy (TPM2_PolicyAuthorize "
                          "failed with TSS/TPM error: 0x%u).\n"), rc);
      goto exit5;
    }

  /* Unseal the key with the policy session that authorizes the signed policy */
  grub_memset (&authCmd, 0, sizeof (authCmd));
  authCmd.sessionHandle = session;
  rc = TPM2_Unseal (sealed_key_handle, &authCmd, &data, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      err = GRUB_ERR_BAD_DEVICE;
      grub_error (err, N_("Failed to unseal sealed key (TPM2_Unseal failed"
                          "with TSS/TPM error: 0x%u).\n"), rc);
      grub_millisleep(500);
      goto exit5;
    }

  /* Epilogue */
  key_out = grub_malloc (data.size);
  if (!key_out)
    {
      err = GRUB_ERR_OUT_OF_MEMORY;
      grub_error (err, N_("No memory left to allocate unlock key buffer"));
      goto exit4;
    }

  grub_printf("TPM2: unsealed %u bytes of key material\n", data.size);

  if (ctx->efivar)
    {
      rc = grub_tpm2_protector_publish_key (data.buffer, data.size, ctx->efivar);
      if (rc)
	goto exit4;
    }

  grub_memcpy (key_out, data.buffer, data.size);

  *key = key_out;
  *key_size = data.size;

  err = GRUB_ERR_NONE;

exit5:
  TPM2_FlushContext (session);

exit4:
  TPM2_FlushContext (sealed_key_handle);

exit3:
  TPM2_FlushContext (primary_handle);

exit2:
  TPM2_FlushContext (pubkey_handle);

exit1:
  grub_free (sealed_key_bytes);
  grub_free (pub_key_bytes);
  grub_free (sig_bytes);

  return err;
}

static grub_err_t
grub_tpm2_protector_recover (const struct grub_tpm2_protector_context *ctx,
                             grub_uint8_t **key, grub_size_t *key_size)
{
  switch (ctx->mode)
    {
    case GRUB_TPM2_PROTECTOR_MODE_SRK:
      return grub_tpm2_protector_srk_recover (ctx, key, key_size);
    case GRUB_TPM2_PROTECTOR_MODE_NV:
      return grub_tpm2_protector_nv_recover (ctx, key, key_size);
    case GRUB_TPM2_PROTECTOR_MODE_AUTHPOL:
      return grub_tpm2_protector_authpol_recover (ctx, key, key_size);
    default:
      return GRUB_ERR_BAD_ARGUMENT;
    }
}

static grub_err_t
grub_tpm2_protector_recover_key (grub_uint8_t **key, grub_size_t *key_size)
{
  grub_err_t err;

  /* Expect a call to tpm2_protector_init before anybody tries to use us */
  if (grub_tpm2_protector_ctx.mode == GRUB_TPM2_PROTECTOR_MODE_UNSET)
    return grub_error (GRUB_ERR_INVALID_COMMAND,
                       N_("Cannot use TPM2 key protector without initializing "
                          "it, call tpm2_protector_init first"));

  if (!key)
    return GRUB_ERR_BAD_ARGUMENT;

  err = grub_tpm2_protector_recover (&grub_tpm2_protector_ctx, key, key_size);
  if (err)
    return err;

  return GRUB_ERR_NONE;
}

static void
initialize_pcr_list (struct grub_tpm2_protector_context *ctx)
{
  TPMS_PCR_SELECTION *pcr_sel;
  grub_uint8_t i;

  grub_memset (&ctx->pcr_list, 0, sizeof (TPML_PCR_SELECTION));

  ctx->pcr_list.count = 1;

  pcr_sel = &ctx->pcr_list.pcrSelections[0];
  pcr_sel->hash = ctx->bank;
  pcr_sel->sizeOfSelect = 3;

  for (i = 0; i < ctx->pcr_count; i++)
    pcr_sel->pcrSelect[TPM2_PCR_TO_SELECT(ctx->pcrs[i])] |= TPM2_PCR_TO_BIT(ctx->pcrs[i]);
}

static grub_err_t
grub_tpm2_protector_check_args (struct grub_tpm2_protector_context *ctx)
{
  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_UNSET && ctx->keyfile &&
      ctx->pkfile && ctx->sigfile)
    ctx->mode = GRUB_TPM2_PROTECTOR_MODE_AUTHPOL;
  else if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_UNSET)
    ctx->mode = GRUB_TPM2_PROTECTOR_MODE_SRK;

  /* Checks for SRK mode */
  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_SRK && !ctx->keyfile)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In SRK mode, a key file must be specified: "
                          "--keyfile or -k"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_SRK && ctx->nv)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In SRK mode, an NV Index cannot be specified"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_SRK && ctx->pkfile)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In SRK mode, an a public key cannot be specified"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_SRK && ctx->sigfile)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In SRK mode, an a signed pcr policy cannot be specified"));

  /* Checks for NV mode */
  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_NV && !ctx->nv)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In NV Index mode, an NV Index must be specified: "
                           "--nvindex or -n"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_NV && ctx->keyfile)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In NV Index mode, a keyfile cannot be specified"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_NV && ctx->srk)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In NV Index mode, an SRK cannot be specified"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_NV && ctx->asymmetric)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In NV Index mode, an asymmetric key type cannot be "
                          "specified"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_NV && ctx->pkfile)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In NV Index mode, an a public key cannot be specified"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_NV && ctx->sigfile)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In NV Index mode, an a signed pcr policy cannot be specified"));

  /* Checks for Authorized Policy mode */
  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_AUTHPOL && !ctx->keyfile)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In Authorized Policy mode, a key file must be specified: "
                          "--keyfile or -k"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_AUTHPOL && !ctx->pkfile)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In Authorized Policy mode, a public key file must be specified: "
                          "--pkfile or -P"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_AUTHPOL && !ctx->sigfile)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In Authorized Policy mode, a signed pcr file must be specified: "
                          "--sigfile or -S"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_AUTHPOL && ctx->nv)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In Authorized Policy mode, an NV Index cannot be specified"));

  /* Defaults assignment */
  if (!ctx->bank)
    ctx->bank = TPM_ALG_SHA256;

  if (!ctx->pcr_count)
    {
      ctx->pcrs[0] = 7;
      ctx->pcr_count = 1;
    }

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_SRK ||
      ctx->mode == GRUB_TPM2_PROTECTOR_MODE_AUTHPOL)
    {
      if (!ctx->srk)
        ctx->srk = TPM2_SRK_HANDLE;

      if (!ctx->asymmetric)
        ctx->asymmetric = TPM_ALG_RSA;
    }

  initialize_pcr_list (ctx);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_parse_string (const char *value, const char **var, const char *arg_name)
{
  if (grub_strlen (value) == 0)
    return GRUB_ERR_BAD_ARGUMENT;

  *var = grub_strdup (value);
  if (!*var)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       N_("No memory to duplicate %s argument"), arg_name);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_parse_keyfile (const char *value, const char **keyfile)
{
  return grub_tpm2_protector_parse_string (value, keyfile, "keyfile");
}

static grub_err_t
grub_tpm2_protector_parse_pkfile (const char *value, const char **pkfile)
{
  return grub_tpm2_protector_parse_string (value, pkfile, "pkfile");
}

static grub_err_t
grub_tpm2_protector_parse_sigfile (const char *value, const char **sigfile)
{
  return grub_tpm2_protector_parse_string (value, sigfile, "sigfile");
}

static grub_err_t
grub_tpm2_protector_parse_efivar (const char *value, const char **efivar)
{
  return grub_tpm2_protector_parse_string (value, efivar, "efivar");
}

static grub_err_t
grub_tpm2_protector_parse_mode (const char *value,
                                grub_tpm2_protector_mode_t *mode)
{
  if (grub_strcmp (value, "srk") == 0)
    *mode = GRUB_TPM2_PROTECTOR_MODE_SRK;
  else if (grub_strcmp (value, "nv") == 0)
    *mode = GRUB_TPM2_PROTECTOR_MODE_NV;
  else if (grub_strcmp (value, "authpol") == 0)
    *mode = GRUB_TPM2_PROTECTOR_MODE_AUTHPOL;
  else
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
                       N_("Value '%s' is not a valid TPM2 key protector mode"),
                       value);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_init_cmd_handler (grub_extcmd_context_t ctxt, int argc,
                                 char **args __attribute__ ((unused)))
{
  struct grub_arg_list *state = ctxt->state;
  grub_err_t err;

  if (argc)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("The TPM2 key protector does not accept any "
                          "non-option arguments (i.e., like -o and/or --option "
                          "only)"));

  grub_free ((void *) grub_tpm2_protector_ctx.keyfile);
  grub_memset (&grub_tpm2_protector_ctx, 0, sizeof (grub_tpm2_protector_ctx));

  if (state[0].set)  /* mode */
    {
      err = grub_tpm2_protector_parse_mode (state[0].arg,
                                            &grub_tpm2_protector_ctx.mode);
      if (err)
        return err;
    }

  if (state[1].set)  /* pcrs */
    {
      err = grub_tpm2_protector_parse_pcrs (state[1].arg,
                                            grub_tpm2_protector_ctx.pcrs,
                                            &grub_tpm2_protector_ctx.pcr_count);
      if (err)
        return err;
    }

  if (state[2].set)  /* bank */
    {
      err = grub_tpm2_protector_parse_bank (state[2].arg,
                                            &grub_tpm2_protector_ctx.bank);
      if (err)
        return err;
    }

  if (state[3].set)  /* keyfile */
    {
      err = grub_tpm2_protector_parse_keyfile (state[3].arg,
                                               &grub_tpm2_protector_ctx.keyfile);
      if (err)
        return err;
    }

  if (state[4].set)  /* srk */
    {
      err = grub_tpm2_protector_parse_tpm_handle (state[4].arg,
                                                  &grub_tpm2_protector_ctx.srk);
      if (err)
        return err;
    }

  if (state[5].set)  /* asymmetric */
    {
      err = grub_tpm2_protector_parse_asymmetric (state[5].arg,
                                                  &grub_tpm2_protector_ctx.asymmetric);
      if (err)
        return err;
    }

  if (state[6].set)  /* nvindex */
    {
      err = grub_tpm2_protector_parse_tpm_handle (state[6].arg,
                                                  &grub_tpm2_protector_ctx.nv);
      if (err)
        return err;
    }

  if (state[7].set)  /* efivar */
    {
      err = grub_tpm2_protector_parse_efivar (state[7].arg,
                                                  &grub_tpm2_protector_ctx.efivar);
      if (err)
        return err;
    }

  if (state[8].set)  /* pkfile */
    {
      err = grub_tpm2_protector_parse_pkfile (state[8].arg,
                                              &grub_tpm2_protector_ctx.pkfile);
      if (err)
        return err;
    }

  if (state[9].set)  /* sigfile */
    {
      err = grub_tpm2_protector_parse_sigfile (state[9].arg,
                                               &grub_tpm2_protector_ctx.sigfile);
      if (err)
        return err;
    }

  err = grub_tpm2_protector_check_args (&grub_tpm2_protector_ctx);

  /* This command only initializes the protector, so nothing else to do. */

  return err;
}

static grub_err_t
grub_tpm2_protector_clear_cmd_handler (grub_extcmd_context_t ctxt __attribute__ ((unused)),
                                       int argc,
                                       char **args __attribute__ ((unused)))
{
  if (argc)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("tpm2_key_protector_clear accepts no arguments"));

  grub_free ((void *) grub_tpm2_protector_ctx.keyfile);
  grub_free ((void *) grub_tpm2_protector_ctx.pkfile);
  grub_free ((void *) grub_tpm2_protector_ctx.sigfile);
  grub_memset (&grub_tpm2_protector_ctx, 0, sizeof (grub_tpm2_protector_ctx));

  return GRUB_ERR_NONE;
}

static struct grub_key_protector grub_tpm2_key_protector =
  {
    .name = "tpm2",
    .recover_key = grub_tpm2_protector_recover_key
  };

GRUB_MOD_INIT (tpm2)
{
  grub_tpm2_protector_init_cmd =
    grub_register_extcmd ("tpm2_key_protector_init",
                          grub_tpm2_protector_init_cmd_handler, 0,
                          N_("[-m mode] "
                             "[-p pcr_list] "
                             "[-b pcr_bank] "
                             "[-k sealed_key_file_path] "
                             "[-s srk_handle] "
                             "[-a asymmetric_key_type] "
                             "[-n nv_index] "
                             "[-P public_key_file_path] "
                             "[-S signature_file_path]"),
                          N_("Initialize the TPM2 key protector."),
                          grub_tpm2_protector_init_cmd_options);
  grub_tpm2_protector_clear_cmd =
    grub_register_extcmd ("tpm2_key_protector_clear",
                          grub_tpm2_protector_clear_cmd_handler, 0, NULL,
                          N_("Clear the TPM2 key protector if previously initialized."),
                          NULL);
  grub_key_protector_register (&grub_tpm2_key_protector);
}

GRUB_MOD_FINI (tpm2)
{
  grub_free ((void *) grub_tpm2_protector_ctx.keyfile);
  grub_free ((void *) grub_tpm2_protector_ctx.pkfile);
  grub_free ((void *) grub_tpm2_protector_ctx.sigfile);
  grub_memset (&grub_tpm2_protector_ctx, 0, sizeof (grub_tpm2_protector_ctx));

  grub_key_protector_unregister (&grub_tpm2_key_protector);
  grub_unregister_extcmd (grub_tpm2_protector_clear_cmd);
  grub_unregister_extcmd (grub_tpm2_protector_init_cmd);
}
