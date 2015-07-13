Pod::Spec.new do |s|

  s.name         = "MCryptoLib"
  s.version      = "0.8.0"
  s.summary      = "A simple PGP, S/MIME and Mynigma encryption library."

  s.description  = <<-DESC 
                   MCryptoLib is a simple, stable, modern, easy-to-use library for PGP, S/MIME and Mynigma encryption support on iOS and Mac OS.
                   DESC

  s.homepage     = "https://mynigma.org"

  s.license      = "GPLv3"

  s.author             = { "Romes" => "roman@mynigma.org" }

  s.ios.deployment_target = "7.0"
  s.osx.deployment_target = "10.8"
 

  s.source       = { :git => "https://github.com/Mynigma/MCryptoLib.git" }


  s.source_files  = "MCryptoLib/**/*.{h,m}"
  
  s.public_header_files = "Classes/**/*.h"

  s.requires_arc = true

  s.ios.dependency "mailcore2-ios"
  s.osx.dependency "mailcore2-osx"

end
