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
require_relative '../utils/git'

module YAVDB
  module Sources
    module Victims
      class Client

        Language = Struct.new(:name, :package_manager, :name_parser)

        REPOSITORY_URL = 'https://github.com/victims/victims-cve-db'.freeze

        LANGUAGES = [
          Language.new('java', 'maven', lambda { |affected_package| "#{affected_package['groupId']}:#{affected_package['artifactId']}" }),
          Language.new('python', 'pypi', lambda { |affected_package| affected_package['name'] })
        ]

        def self.advisories
          LANGUAGES.map do |language|
            glob = language_glob(language.name)
            YAVDB::SourceTypes::GitRepo.search(glob, REPOSITORY_URL).map do |repo_path, file_paths|
              Dir.chdir(repo_path) do
                file_paths.map do |file_path|
                  advisory_hash = YAML.load_file(file_path)
                  url           = "#{REPOSITORY_URL}/blob/master/#{file_path}"
                  create(advisory_hash, language, url)
                end
              end
            end
          end.flatten
        end

        class << self

          private

          def language_glob(language)
            "database/#{language}/*/*.*"
          end

          def create(advisory_hash, language, url)
            advisory_hash['affected'].map do |affected_package|
              vuln_id_stamp = advisory_hash['cve'] || 'date'
              vuln_id       = "victims:#{language.package_manager}:#{language.name_parser[affected_package]}:#{vuln_id_stamp}"

              YAVDB::Advisory.new(
                vuln_id,
                advisory_hash['title'],
                advisory_hash['description'],
                language.name_parser[affected_package],
                affected_package['version'],
                affected_package['unaffected'],
                affected_package['fixedin'],
                severity(advisory_hash['cvss_v2']),
                language.package_manager,
                [advisory_hash['cve']],
                nil, #:cwe
                nil, #:osvdb
                nil, #:cvss_v2_vector
                advisory_hash['cvss_v2'],
                nil, #:cvss_v3_vector
                nil, #:cvss_v3
                nil,
                nil,
                nil,
                ['Victims CVE Database'],
                advisory_hash['references'],
                url
              )
            end.flatten
          end

          def severity(cvss_score)
            case cvss_score
              when 0.0..3.3 then
                'low'
              when 3.3..6.6 then
                'medium'
              else
                'high'
            end
          end

        end

      end
    end
  end
end
