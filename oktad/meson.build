project('oktad', 'c')

yacc = find_program('yacc')
yacc_gen = generator(
	yacc,
	output: '@BASENAME@.c',
	arguments: ['-o', '@OUTPUT@', '@INPUT@']
)

parser = yacc_gen.process('parse.y')

bsd_dep = dependency('libbsd', required: true)
curl_dep = dependency('libcurl', required: true)
json_dep = dependency('json-c', required: true)
jwt_dep = dependency('libjwt', required: true)

executable(
	'oktad',
	['oktad.c', 'log.c', parser],
	dependencies: [ bsd_dep, curl_dep, json_dep, jwt_dep ],
)
