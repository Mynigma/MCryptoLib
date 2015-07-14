Pod::Spec.new do |s|

  s.name         = "MCryptoLib"
  s.version      = "0.8.1"
  s.summary      = "A simple PGP, S/MIME and Mynigma encryption library."

  s.description  = <<-DESC 
                   MCryptoLib is a simple, stable, modern, easy-to-use library for PGP, S/MIME and Mynigma encryption support on iOS and Mac OS X.
                   DESC

  s.homepage     = "https://mynigma.org"

  s.license      = "GPLv3"

  s.author       = { "Romes" => "roman@mynigma.org" }

  s.ios.deployment_target = "7.0"
  s.osx.deployment_target = "10.8"
 

  s.source       = { :git => "https://github.com/Mynigma/MCryptoLib.git" }


  s.source_files  = "MCryptoLib/**/*.{h,m,mm,c,cc}"
  
  s.public_header_files = "MCryptoLib/**/*.h"

  s.requires_arc = true

  s.resource_bundles = { 'MCryptoLib' => "MCryptoLib/**/*.{xcdatamodeld, jpg, html, txt}" }

  s.dependency 'OpenSSL', '~> 1.0'
  s.dependency 'MProtoBuf'
end
