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
    module RubyAdvisory
      class Client

        REPOSITORY_URL  = 'https://github.com/rubysec/ruby-advisory-db'.freeze
        PACKAGE_MANAGER = 'rubygems'.freeze

        def self.advisories
          YAVDB::SourceTypes::GitRepo.search('gems/**/*.yml', REPOSITORY_URL).map do |repo_path, file_paths|
            Dir.chdir(repo_path) do
              file_paths.map do |file_path|
                advisory_hash = YAML.load_file(file_path)
                create(file_path, advisory_hash)
              end
            end
          end.flatten
        end

        class << self

          private

          def create(_file_path, advisory_hash)
            date                = Date.strptime(advisory_hash['date'].to_s, '%Y-%m-%d')
            severity            = severity(advisory_hash['cvss_v2'], advisory_hash['cvss_v3'])
            cve                 = advisory_hash['cve'] && "CVE-#{advisory_hash['cve']}"
            osvdb               = advisory_hash['osvdb'] && "OSVDB-#{advisory_hash['osvdb']}"
            references          = references(advisory_hash)
            vulnerable_versions = if advisory_hash['unaffected_versions'] || advisory_hash['patched_versions']
                                    nil
                                  else
                                    ['*']
                                  end

            vuln_id_stamp = cve || osvdb || date
            vuln_id       = "rubyadvisory:rubygems:#{advisory_hash['gem']}:#{vuln_id_stamp}"

            YAVDB::Advisory.new(
              vuln_id,
              advisory_hash['title'],
              advisory_hash['description'],
              advisory_hash['gem'],
              clean_version(vulnerable_versions),
              clean_version(advisory_hash['unaffected_versions']),
              clean_version(advisory_hash['patched_versions']),
              severity,
              PACKAGE_MANAGER,
              cve,
              nil, #:cwe
              advisory_hash['osvdb'],
              nil, #:cvss_v2_vector
              advisory_hash['cvss_v2'],
              nil, #:cvss_v3_vector
              advisory_hash['cvss_v3'],
              date,
              date,
              date,
              ['Rubysec'],
              references,
              advisory_hash['url']
            )
          end

          def clean_version(versions)
            versions&.map { |version| version.tr(',', ' ') }
          end

          def references(advisory_hash)
            references = [REPOSITORY_URL]

            if advisory_hash['related'] && advisory_hash['related']['url']
              references.concat(advisory_hash['related']['url'])
            else
              references
            end
          end

          def severity(cvss_v2_score, cvss_v3_score)
            if cvss_v3_score
              severity_level(cvss_v3_score)
            elsif cvss_v2_score
              severity_level(cvss_v2_score)
            end
          end

          def severity_level(cvss_score)
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
