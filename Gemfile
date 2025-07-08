# frozen_string_literal: true

# start of the  Modification 
# frozen_string_literal: true
source "https://rubygems.org"

# Main theme (must stay at 7.3)
gem "jekyll-theme-chirpy", "~> 7.3"

# Force compatible sass processor
gem 'sassc', '~> 2.0'
gem 'jekyll-sass-converter', '1.5.2' # Last version before sass-embedded

# System dependencies
gem 'ffi', '~> 1.17', platform: :ruby
gem 'google-protobuf', '~> 3.21', platform: :ruby

# Testing
group :test do
  gem "html-proofer", "~> 5.0"
end

# Windows-specific
platforms :mingw, :x64_mingw, :mswin do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
  gem "wdm", "~> 0.2.0"
end

# End of the modification

#source "https://rubygems.org"

#gem "jekyll-theme-chirpy", "~> 7.3"

#gem "html-proofer", "~> 5.0", group: :test

#platforms :mingw, :x64_mingw, :mswin, :jruby do
#  gem "tzinfo", ">= 1", "< 3"
#  gem "tzinfo-data"
# end

# gem "wdm", "~> 0.2.0", :platforms => [:mingw, :x64_mingw, :mswin]

