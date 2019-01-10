# yavdb - The Free and Open Source vulnerability database
# Copyright (C) 2017-present Rodrigo Fernandes
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

require 'date'
require 'yaml'

require_relative '../dtos/advisory'
require_relative '../source_types/git_repo'

module YAVDB
  module Sources
    module FriendsOfPHP
      class Client

        REPOSITORY_URLS = [
          'https://github.com/FriendsOfPHP/security-advisories',
          'https://github.com/Cotya/magento-security-advisories'
        ].freeze

        PACKAGE_MANAGER = 'packagist'.freeze

        def self.advisories
          REPOSITORY_URLS.map do |repository_url|
            YAVDB::SourceTypes::GitRepo.search('*/*/*.yaml', repository_url).map do |repo_path, file_paths|
              Dir.chdir(repo_path) do
                file_paths.map do |file_path|
                  advisory_hash = YAML.load_file(file_path)
                  url           = "#{repository_url}/blob/master/#{file_path}"
                  filename      = File.basename(file_path, '.yaml')
                  create(url, filename, advisory_hash)
                end
              end
            end
          end.flatten
        end

        def self.create(url, filename, advisory_hash)
          date = Date.parse('1970-01-01')

          versions = advisory_hash['branches'].map do |_, info|
            date = Date.strptime(info['time'].to_s, '%Y-%m-%d %H:%M:%S') if info['time']
            info['versions'].join(' ')
          end.flatten

          cves = [advisory_hash['cve']].reject { |cve| cve == '~' }

          package_name = advisory_hash['reference'].gsub(%r{composer:\/\/(.*)}, '\1')

          vuln_id = "friendsofphp:packagist:#{package_name}:#{filename}"

          YAVDB::Advisory.new(
            vuln_id,
            advisory_hash['title'],
            nil, #:description
            package_name,
            versions, #:vulnerable_versions
            nil, #:unaffected_versions
            nil, #:patched_versions
            nil, #:severity
            PACKAGE_MANAGER,
            cves,
            nil, #:cwe
            nil, #:osvdb
            nil, #:cvss_v2_vector
            nil, #:cvss_v2
            nil, #:cvss_v3_vector
            nil, #:cvss_v3
            date,
            date,
            date,
            ['FriendsOfPHP'],
            [advisory_hash['link']],
            url
          )
        end

      end
    end
  end
end
