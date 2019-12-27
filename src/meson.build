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
if cc.get_id() == 'msvc'
	asm_extension = '.asm'
endif

asm = files('asm/trampoline-@0@@1@'.format(arch, asm_extension))

if cc.get_id() == 'msvc'
	if bitness == 32
		masm = find_program('ml')
	else
		masm = find_program('ml64')
	endif

	masm_gen = generator(masm,
		output: '@BASENAME@.obj',
		depfile: '@BASENAME@.obj.ndep',
		arguments: [
			'/I', '@CURRENT_SOURCE_DIR@/asm/',
			'/I', '@0@/'.format(meson.current_build_dir()),
			'/safeseh',
			'@EXTRA_ARGS@',
			'/Fo', '@OUTPUT@',
			'/c',
			'@INPUT@',
		])

	asm += 'asm/setjmp-@0@@1@'.format(arch, asm_extension)

	sources += masm_gen.process(asm)
else
	sources += asm
endif

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
