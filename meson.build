project(
  'purple-trillian',
  'cpp',
  version: '0.1.0',
)

SOURCES = [
  'main.cpp',
  'tests.cpp',
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

shared_library(
  meson.project_name(),
  SOURCES,
  dependencies: [PURPLE],
  install: true,
  install_dir: PURPLE.get_pkgconfig_variable('plugindir'),
  cpp_args: ['-std=c++17']
)

executable(
  'a',
  SOURCES + ['debug.cpp'],
  dependencies: [PURPLE],
  install: false,
  cpp_args: ['-O0', '-g3', '-fsanitize=address', '-std=c++17', '-Wall', '-Wextra', '-Wno-unused-parameter', '-Wsign-conversion'],
  link_args: ['-fsanitize=address']
)
