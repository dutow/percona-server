#ifndef MYSQLPP_SERVICE_TRAITS_FWD_HPP
#define MYSQLPP_SERVICE_TRAITS_FWD_HPP

namespace mysqlpp {

// specialization for concrete SERVICE must include the following method
// static const char *get_service_name() noexcept;
template <typename Service>
struct service_traits;

}  // namespace mysqlpp

#endif
