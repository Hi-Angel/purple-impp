project(
  'purple-impp',
  'cpp',
  version: '0.1.0',
)

SOURCES = [
  'main.cpp',
  'show.cpp',
  'serialize.cpp',
  'utils.cpp'
]

add_project_arguments(
  '-DPREFIX="@0@"'.format(get_option('prefix')),
  '-DLIBDIR="@0@"'.format(get_option('libdir')),
  '-DPLUGIN_VERSION="@0@"'.format(meson.project_version()),
  language : 'cpp'
)

PURPLE = dependency('purple', version: '>=2.0.0')
ZLIB = dependency('zlib')
GLOBAL_DEPS = [PURPLE, ZLIB]

shared_library(
  meson.project_name(),
  SOURCES,
  dependencies: GLOBAL_DEPS,
  install: true,
  install_dir: PURPLE.get_pkgconfig_variable('plugindir'),
  cpp_args: ['-std=c++17']
)

shared_library(
  'trillian_preload',
  SOURCES + ['trillian_preload.cpp'],
  dependencies: GLOBAL_DEPS,
  install: false,
  cpp_args: ['-std=c++17'],
  link_args: [ '-Wl,--no-as-needed', '-lssl', '-ldl' ]
)

executable(
  'a',
  SOURCES + ['debug.cpp'],
  dependencies: GLOBAL_DEPS,
  install: false,
  cpp_args: ['-O0', '-g3', '-fsanitize=address', '-std=c++17', '-Wall', '-Wextra', '-Wno-unused-parameter', '-Wsign-conversion'],
  link_args: ['-fsanitize=address']
)
