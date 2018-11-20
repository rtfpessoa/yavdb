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

require 'execjs'
require 'oga'
require 'oga/xml/entities'

require_relative '../dtos/advisory'
require_relative '../utils/http'

module YAVDB
  module Sources
    module NPMJS
      class Client

        API_URL = 'https://www.npmjs.com'

        def self.advisories
          packages = fetch_packages_recursive(0)
          parse_vulnerabilities(packages)
        end

        class << self

          private

          def fetch_packages_recursive(page_number)
            page = get_page_html(get_page_url(page_number), false, 'npmjs/feed')

            script_tag = page.css('script').find { |script| script.text.include?('window.__context__') }.text
            context = ExecJS.compile("var window = {};\n#{script_tag.force_encoding('utf-8')};")
            advisory_data = context.exec('return window.__context__.context.advisoriesData')

            packages = advisory_data['objects']

            next_url = advisory_data['urls']['next']
            next_packages = if next_url && !next_url&.include?("page=#{page_number}")
                              fetch_packages_recursive(page_number + 1)
                            else
                              []
                            end

            packages.concat(next_packages)
          end

          def parse_vulnerabilities(packages)
            packages.map { |package| create(package) }.flatten
          end

          def create(package)
            published_date = Date.strptime(package['created'], '%s')
            updated_date   = Date.strptime(package['updated'], '%s')

            cves = package['cves'] || []

            versions = [package['vulnerable_versions']]
            versions = ['*'] unless versions.any?

            vuln_id = "npmjs:npm:#{package['module_name']}:#{package['id']}"

            YAVDB::Advisory.new(
              vuln_id,
              package['title'],
              package['overview'],
              package['module_name'],
              versions,
              nil, #:unaffected_versions
              nil, #:patched_versions
              package['severity'],
              'npm',
              cves,
              package['cwe'],
              nil, #:osvdb
              nil, #:cvss_v2_vector
              nil, #:cvss_v2_score
              nil, #:cvss_v3_vector
              nil, #:cvss_v3_score
              published_date,
              published_date,
              updated_date,
              package['found_by']['name'],
              package['url'],
              package['url']
            )
          end

          def get_page_html(source_url, with_cache, group_cache_key)
            body_lines = YAVDB::Utils::HTTP.get_page_contents(source_url, with_cache, group_cache_key)
            Oga.parse_html(body_lines, :strict => true)
          end

          def get_page_url(page)
            "#{API_URL}/advisories?page=#{page}&perPage=300&order=-id"
          end

        end

      end
    end
  end
end
