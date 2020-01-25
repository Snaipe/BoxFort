sh   = find_program('sh', required: false)
cram = find_program('cram', 'cram3', required: false)
if sh.found() and cram.found()
	env = environment()
	env.prepend('PATH',
			join_paths(meson.current_build_dir(), '..', 'sample'),
			join_paths(meson.current_build_dir(), '..', 'sample'))
	env.set('LC_ALL', 'en_US.utf8')
	env.set('MSYS2_ARG_CONV_EXCL', '--filter=')
	env.set('TERM', 'dumb')

	test('cram tests', cram,
			args: [join_paths(meson.current_source_dir(), 'cram')],
			env: env)
endif
