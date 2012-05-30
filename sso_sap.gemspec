Gem::Specification.new do |gem|
  gem.name          = 'sso_sap'
  gem.version       = '0.1.0'
  gem.summary       = %q{Single Sign-On using SAP logon tickets.}
  gem.description   = %q{Single Sign-On using SAP logon tickets.}

  gem.authors       = ['Daniel Stutzman', 'Brent Ertz']
  gem.email         = 'daniel@quickleft.com'
  gem.homepage      = 'https://github.com/danielstutzman/sso_sap'

  gem.add_development_dependency 'rspec', '2.8'

  gem.files         = ['README.md'] + Dir['lib/**/*.rb']
  gem.test_files    = Dir['spec/**/*.rb']
  gem.require_paths = ['lib']
end
