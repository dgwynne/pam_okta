project('pam_okta', 'c')

cc = meson.get_compiler('c')
pam_dep = cc.find_library('pam', required: true)

shared_library(
	'pam_okta',
	['pam_okta.c'],
	name_prefix: '',
	dependencies: pam_dep
)
