yacc = find_program('yacc')
yacc_gen = generator(
	yacc,
	output: '@BASENAME@.c',
	arguments: ['-o', '@OUTPUT@', '@INPUT@']
)

parser = yacc_gen.process('parse.y')

bsd_dep = dependency('libbsd', required: true)
curl_dep = dependency('libcurl', required: true)
json_dep = dependency('jansson', required: true)
jwt_dep = dependency('libjwt', required: true)

progname = 'pam_oktad'
sbindir = get_option('sbindir')

conf = configuration_data()
conf.set('prefix', get_option('prefix'))
conf.set('sbindir', sbindir)
conf.set('progname', progname)

executable(
	progname,
	['oktad.c', 'log.c', parser],
	dependencies: [ bsd_dep, curl_dep, json_dep, jwt_dep ],
	install: true,
	install_dir: sbindir,
)

systemd = dependency('systemd')

unit_file = configure_file(
	input: 'pam_oktad.service.in',
	output: 'pam_oktad.service',
	configuration: conf,
)

install_data(
	unit_file,
	install_dir: systemd.get_variable(pkgconfig: 'systemdsystemunitdir'),
)

install_man(['pam_oktad.8', 'pam_oktad.conf.5'])
