#include "crypto_store_permission.h"

#include <string>

namespace node {

namespace permission {

void CryptoStorePermission::Apply(Environment* env,
                                  const std::vector<std::string>& allow,
                                  PermissionScope scope) {
  allow_crypto_store_ = true;
}

void CryptoStorePermission::Drop(Environment* env,
                                 PermissionScope scope,
                                 const std::string_view& param) {
  allow_crypto_store_ = false;
}

bool CryptoStorePermission::is_granted(Environment* env,
                                       PermissionScope perm,
                                       const std::string_view& param) const {
  return allow_crypto_store_;
}

}  // namespace permission
}  // namespace node
