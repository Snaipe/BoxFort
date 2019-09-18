sources = files(
	'addr.c',
	'addr.h',
	'arena.c',
	'arena.h',
	'context.c',
	'context.h',
	'exe.h',
	'exe-@0@.c'.format(binfmt),
	'exe-@0@.h'.format(binfmt),
	'sandbox-@0@.c'.format(os_family),
	'sandbox-@0@.h'.format(os_family),
	'sandbox.c',
	'sandbox.h',
	'timeout-@0@.c'.format(os_family),
	'timeout.h',
	'timestamp.c',
	'timestamp.h',
)

asm_extension = '.S'
asm = files('asm/trampoline-@0@@1@'.format(arch, asm_extension))
if target_machine.system() == 'windows'
	asm += 'asm/setjmp-@0@@1@'.format(arch, asm_extension)
endif

sources += asm

configure_file(input         : 'config.h.in',
               output        : 'config.h',
               configuration : config)

deps = [
	threads,
	librt,
	libm,
]

boxfort = library('boxfort', sources,
	include_directories: [boxfort_includedir],
	version: '3.1.0',
	dependencies: deps,
	install: true,
	link_args: cc.get_supported_link_arguments([
		'-Wl,--exclude-libs,ALL',
	]),
)

pkgconfig = import('pkgconfig')
pkgconfig.generate(
	name: meson.project_name(),
	description: 'A portable process sandboxing library',
	url: 'https://snai.pe/git/boxfort',
)
