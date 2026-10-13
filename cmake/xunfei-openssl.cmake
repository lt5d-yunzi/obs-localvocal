# === 讯飞 ASR / 机器翻译：OpenSSL 查找模块（新增） ===
#
# 背景：
#   libobs 的 obs-deps 预编译包**不提供 OpenSSL**（上游只在 Linux 上 find_package(OpenSSL)，
#   macOS/Windows 的 curl 依赖走各自系统 TLS 框架）。而讯飞插件需要一个 TLS 后端来跑 wss://，
#   所以这里自己做一次跨平台查找：
#
#   1) 先让 CMake 默认查找（Linux 系统 OpenSSL / 用户已设置的 OpenSSL_ROOT_DIR）
#   2) 再用 pkg-config
#   3) 最后在平台常见位置兜底（macOS 的 Homebrew、Windows 的 vcpkg / Program Files）
#
#   **找不到不会让构建失败**，而是把 XUNFEI_HAVE_OPENSSL 置为 FALSE，
#   由 CMakeLists.txt 关闭讯飞功能并给出提示——这样插件本体在任何平台都能正常构建。
#
# 如需强制指定：cmake -DOpenSSL_ROOT_DIR=/path/to/openssl ...

set(XUNFEI_HAVE_OPENSSL FALSE)

# --- 1) CMake 默认查找 ---
find_package(OpenSSL QUIET COMPONENTS SSL Crypto)

# --- 2) pkg-config 兜底 ---
if(NOT OpenSSL_FOUND)
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(PC_OPENSSL QUIET openssl libssl)
    if(PC_OPENSSL_FOUND)
      set(OpenSSL_FOUND TRUE)
      set(OpenSSL_INCLUDE_DIR "${PC_OPENSSL_INCLUDEDIR}")
      set(OpenSSL_SSL_LIBRARY "${PC_OPENSSL_LIBDIR}/libssl${CMAKE_SHARED_LIBRARY_SUFFIX}")
      set(OpenSSL_CRYPTO_LIBRARY "${PC_OPENSSL_LIBDIR}/libcrypto${CMAKE_SHARED_LIBRARY_SUFFIX}")
      message(STATUS "讯飞: 通过 pkg-config 找到 OpenSSL ${PC_OPENSSL_VERSION}")
    endif()
  endif()
endif()

# --- 3) 平台常见位置兜底 ---
# 可用 -DXUNFEI_OPENSSL_HINTS=/a;/b 覆盖；设为空字符串则跳过这一步
set(XUNFEI_OPENSSL_HINTS "" CACHE STRING
    "额外的 OpenSSL 查找路径（分号分隔）；置空则使用平台默认位置")
if(NOT OpenSSL_FOUND)
  set(_xf_ssl_hints "${XUNFEI_OPENSSL_HINTS}")
  if(_xf_ssl_hints STREQUAL "")
    if(APPLE)
      list(APPEND _xf_ssl_hints
           /opt/homebrew/opt/openssl@3
           /opt/homebrew/opt/openssl
           /usr/local/opt/openssl@3
           /usr/local/opt/openssl)
    elseif(WIN32)
      file(GLOB _vcpkg_roots "C:/vcpkg/installed/*-windows")
      list(APPEND _xf_ssl_hints ${_vcpkg_roots}
           "C:/Program Files/OpenSSL"
           "C:/OpenSSL-Win64"
           "C:/Program Files/OpenSSL-Win64")
    endif()
  endif()

  foreach(_hint IN LISTS _xf_ssl_hints)
    if(EXISTS "${_hint}/include/openssl/ssl.h")
      set(_xf_ssl_libdir "${_hint}/lib")
      find_library(XF_SSL_LIB NAMES ssl libssl PATHS "${_xf_ssl_libdir}" NO_DEFAULT_PATH)
      find_library(XF_CRYPTO_LIB NAMES crypto libcrypto PATHS "${_xf_ssl_libdir}" NO_DEFAULT_PATH)
      if(XF_SSL_LIB AND XF_CRYPTO_LIB)
        set(OpenSSL_FOUND TRUE)
        set(OpenSSL_INCLUDE_DIR "${_hint}/include")
        set(OpenSSL_SSL_LIBRARY "${XF_SSL_LIB}")
        set(OpenSSL_CRYPTO_LIBRARY "${XF_CRYPTO_LIB}")
        message(STATUS "讯飞: 在 ${_hint} 找到 OpenSSL")
        break()
      endif()
    endif()
  endforeach()
endif()

# --- 架构校验（macOS Universal 构建的关键） ---
# CI 在 arm64 的 macOS runner 上跑 x86_64 构建，而 Homebrew 的 OpenSSL 是 arm64-only：
#   ld: ignoring file '.../libcrypto.3.dylib': found architecture 'arm64',
#       required architecture 'x86_64'
# 结果是编译通过、链接阶段一堆 undefined symbols。这里提前判断，架构不匹配就按「未找到」处理。
if(OpenSSL_FOUND AND APPLE)
  # 目标架构从哪来？按可靠性排序：
  #   1) 环境变量 MACOS_ARCH —— localvocal 的 CI 为每个矩阵项显式设置（如 arm64 / x86_64），最可靠
  #   2) CMAKE_OSX_ARCHITECTURES —— 但它常是 Xcode 的 "$(ARCHS_STANDARD)" 字面量，无法静态判断
  #   3) 都没有时，退回宿主机架构
  set(_xf_want_archs "")
  if(DEFINED ENV{MACOS_ARCH} AND NOT "$ENV{MACOS_ARCH}" STREQUAL "")
    set(_xf_want_archs "$ENV{MACOS_ARCH}")
  elseif(CMAKE_OSX_ARCHITECTURES AND NOT CMAKE_OSX_ARCHITECTURES MATCHES "^\\$\\(")
    set(_xf_want_archs "${CMAKE_OSX_ARCHITECTURES}")
  else()
    execute_process(COMMAND uname -m OUTPUT_VARIABLE _xf_host_arch OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(_xf_want_archs "${_xf_host_arch}")
    message(STATUS
      "讯飞: MACOS_ARCH 未设置且 CMAKE_OSX_ARCHITECTURES 不可静态判断"
      "（${CMAKE_OSX_ARCHITECTURES}），按宿主机架构 ${_xf_host_arch} 校验")
  endif()

  # 挑一个真实的库文件来探架构。
  # 注意：FindOpenSSL 提供的变量名是全大写（OPENSSL_CRYPTO_LIBRARY），
  # 小写形式（OpenSSL_CRYPTO_LIBRARY）只在部分 CMake 版本里存在，这里两种都认。
  set(_xf_probe_lib "")
  foreach(_cand IN ITEMS
          "${OPENSSL_CRYPTO_LIBRARY}" "${OpenSSL_CRYPTO_LIBRARY}"
          "${OPENSSL_SSL_LIBRARY}" "${OpenSSL_SSL_LIBRARY}")
    if(_cand AND NOT _xf_probe_lib AND EXISTS "${_cand}")
      set(_xf_probe_lib "${_cand}")
    endif()
  endforeach()

  if(_xf_probe_lib)
    execute_process(COMMAND lipo -archs "${_xf_probe_lib}"
                    OUTPUT_VARIABLE _xf_lib_archs
                    ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT _xf_lib_archs)
      # lipo 不认（例如符号链接/薄库），退回 file 命令
      execute_process(COMMAND file "${_xf_probe_lib}" OUTPUT_VARIABLE _xf_file_out ERROR_QUIET)
      string(REGEX MATCHALL "arm64|x86_64" _xf_lib_archs "${_xf_file_out}")
      string(REPLACE ";" " " _xf_lib_archs "${_xf_lib_archs}")
    endif()
    message(STATUS "讯飞: 目标架构=[${_xf_want_archs}] OpenSSL 库架构=[${_xf_lib_archs}] (${_xf_probe_lib})")

    foreach(_arch IN LISTS _xf_want_archs)
      if(NOT _xf_lib_archs MATCHES "${_arch}")
        message(WARNING
          "讯飞: OpenSSL 库不包含所需架构 ${_arch}（库架构: ${_xf_lib_archs}）。\n"
          "  为避免出现 'Undefined symbols' 链接错误，本次构建将不启用讯飞功能。\n"
          "  如需在 Universal 构建中启用，请提供同时包含 arm64 与 x86_64 的 OpenSSL，"
          "例如 -DOpenSSL_ROOT_DIR=<universal-openssl>。")
        set(OpenSSL_FOUND FALSE)
        break()
      endif()
    endforeach()
  endif()
endif()

# --- 组装一个统一的导入目标 xunfei_openssl，供链接使用 ---
if(OpenSSL_FOUND)
  if(TARGET OpenSSL::SSL)
    # 默认查找路径已经生成了目标
    add_library(xunfei_openssl INTERFACE)
    target_link_libraries(xunfei_openssl INTERFACE OpenSSL::SSL OpenSSL::Crypto)
    set(XUNFEI_HAVE_OPENSSL TRUE)
  elseif(OpenSSL_INCLUDE_DIR AND OpenSSL_SSL_LIBRARY AND OpenSSL_CRYPTO_LIBRARY)
    add_library(xunfei_openssl UNKNOWN IMPORTED)
    set_target_properties(xunfei_openssl PROPERTIES
      IMPORTED_LOCATION "${OpenSSL_SSL_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${OpenSSL_INCLUDE_DIR}"
      INTERFACE_LINK_LIBRARIES "${OpenSSL_CRYPTO_LIBRARY}")
    set(XUNFEI_HAVE_OPENSSL TRUE)
    message(STATUS "讯飞: OpenSSL include=${OpenSSL_INCLUDE_DIR}")
  endif()
endif()

if(NOT XUNFEI_HAVE_OPENSSL)
  message(WARNING
    "讯飞: 未找到 OpenSSL。将编译出一个**不含讯飞语音识别/机器翻译**的插件。\n"
    "  如需启用，请安装 OpenSSL 开发包后重新配置，例如：\n"
    "    macOS : brew install openssl@3  (通常可自动找到)\n"
    "    Linux : apt install libssl-dev\n"
    "    Windows: vcpkg install openssl 或安装 Win64 OpenSSL，"
    "然后 -DOpenSSL_ROOT_DIR=<路径>")
endif()
