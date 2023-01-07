/^#@INSERT_SYS_SELECT_H@/ d
/^@FALLBACK_SOCKLEN_T@/ d
/^# *include <stdlib\.h>/ d
/^# *include <string\.h>/ d
/^# *include <winsock2\.h>/ d
/^# *include <ws2tcpip\.h>/ d
/^# *include <time\.h>/ d
/^# *include <sys\/socket\.h>/ d
/^# *include <sys\/time\.h>/ d
/^  typedef long ssize_t;/ d
/^  typedef int  pid_t;/ d
/^# *include <gpg-error\.h>/ s,#include <gpg-error.h>,#include <grub/gcrypt/gpg-error.h>,
/^typedef gpg_error_t gcry_error_t;/ d
/^typedef gpg_err_code_t gcry_err_code_t;/ d
/^typedef struct gcry_mpi \*gcry_mpi_t;/ d
/^struct gcry_sexp;/ d
/^typedef struct gcry_sexp \*gcry_sexp_t;/ d
/^struct gcry_md_context;/ d
/^typedef struct gcry_md_handle\s*$/,/^} \*gcry_md_hd_t;/ d
s,_GCRT_GCC_VERSION,_GCRY_GCC_VERSION,g
s,_gcry_mpi_invm,gcry_mpi_invm,g
s,gcry_mpi_get_nbits,_gcry_mpi_get_nbits,g
p
