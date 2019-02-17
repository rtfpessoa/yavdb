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
require 'toml-rb'

require_relative '../dtos/advisory'
require_relative '../source_types/git_repo'

module YAVDB
  module Sources
    module RustSec
      class Client

        REPOSITORY_URL = 'https://github.com/RustSec/advisory-db'.freeze
        PACKAGE_MANAGER = 'cargo'.freeze

        def self.advisories
          YAVDB::SourceTypes::GitRepo.search('crates/**/*.toml', REPOSITORY_URL).map do |repo_path, file_paths|
            Dir.chdir(repo_path) do
              file_paths.map do |file_path|
                advisory_hash = TomlRB.load_file(file_path)
                create(advisory_hash['advisory'])
              end
            end
          end.flatten
        end

        class << self

          private

          def create(advisory_hash)
            date = Date.strptime(advisory_hash['date'].to_s, '%Y-%m-%d')
            severity = 'high' # since no value is provided will use highest
            cve = advisory_hash['aliases']&.select { |a| a.start_with?('CVE') }
            references = advisory_hash['url'] && [advisory_hash['url']]

            vuln_id = "rustsec:cargo:#{advisory_hash['package']}:#{advisory_hash['id']}"

            YAVDB::Advisory.new(
              vuln_id,
              advisory_hash['title'],
              advisory_hash['description'],
              advisory_hash['package'],
              nil,
              advisory_hash['unaffected_versions'],
              advisory_hash['patched_versions'],
              severity,
              PACKAGE_MANAGER,
              cve,
              nil, #:cwe
              nil,
              nil, #:cvss_v2_vector
              nil,
              nil, #:cvss_v3_vector
              nil,
              date,
              date,
              date,
              ['RustSec'],
              references,
              generate_url(advisory_hash)
            )
          end

          def generate_url(advisory_hash)
            "#{REPOSITORY_URL}/blob/master/crates/#{advisory_hash['package']}/#{advisory_hash['id']}.toml"
          end

        end

      end
    end
  end
end
