# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |s|
  s.name          = "fluent-plugin-juniper-telemetry_tech-mocha"
  s.version       = '0.4.2'
  s.authors       = ["Tech Mocha"]
  s.email         = ["jag@openeye.ca"]

  s.description   = %q{Input plugin for Fluentd for Juniper devices telemetry data streaming : Jvision / analyticsd etc ..}
  s.summary       = %q{Input plugin for Fluentd for Juniper devices telemetry data streaming : Jvision / analyticsd etc ..}
  s.homepage      = "https://github.com/tech-mocha/fluentd-plugin-juniper-telemetry"
  s.license       = 'Apache 2.0'

  #s.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^test/}) }
  s.files         = Dir['lib/fluent/plugin/parser*.rb', 'lib/*.rb', 'lib/google/protobuf/*.rb' ]
  s.test_files    = s.files.grep(%r{^(test|spec|features)/})
  s.require_paths = %w(lib)

  s.add_runtime_dependency "fluentd", ">= 0.12.29"
  s.add_runtime_dependency "protobuf"
  s.add_development_dependency "rake"
end

