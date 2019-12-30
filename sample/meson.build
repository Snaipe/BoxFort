samples = [
	'nested.c',
	'callback.c',
	'timeout.c',
	'context.c',
]

foreach sample : samples
	e = executable(sample + '.bin', sample,
			include_directories: includedir,
			dependencies: [libm],
			link_with: libboxfort,
			c_args: [
				cc.get_supported_arguments([
					'-fvisibility=default',
				])
			])
	test(sample, e)
endforeach
