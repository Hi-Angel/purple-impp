project(
  'purple-impp',
  'cpp',
  version: '0.1.0',
  meson_version: '>=0.53.0'
)

SOURCES = [
  'main.cpp',
  'show.cpp',
  'serialize.cpp',
  'utils.cpp',
  'comm.cpp'
]

cxx = meson.get_compiler('cpp')

PURPLE      = dependency('purple', version: '>=2.0.0', include_type: 'system')
ZLIB        = dependency('zlib')
LIBDL       = cxx.find_library('dl')
LIBSSL      = cxx.find_library('ssl')
GLOBAL_DEPS = [PURPLE, ZLIB, LIBDL, LIBSSL]
CXX_FLAGS = ['-Wall', '-Wextra', '-Wno-unused-parameter', '-Wsign-conversion', '-Wswitch-default', '-Wswitch-enum', '-std=c++17',
             get_option('buildtype') == 'debug'? ['-O0', '-g3', '-D_GLIBCXX_DEBUG'] : []]

add_project_arguments(
  '-DPREFIX="@0@"'.format(get_option('prefix')),
  '-DLIBDIR="@0@"'.format(get_option('libdir')),
  '-DPLUGIN_VERSION="@0@"'.format(meson.project_version()),
  CXX_FLAGS,
  language : 'cpp'
)

shared_library(
  meson.project_name(),
  SOURCES,
  dependencies: GLOBAL_DEPS,
  install: true,
  install_dir: PURPLE.get_pkgconfig_variable('plugindir'),
)

shared_library(
  'trillian_preload',
  SOURCES + ['trillian_preload.cpp'],
  dependencies: GLOBAL_DEPS,
  install: false,
)

executable(
  'a',
  SOURCES + ['debug.cpp'],
  dependencies: GLOBAL_DEPS,
  install: false,
  override_options: ['b_sanitize=address,undefined'],
)
