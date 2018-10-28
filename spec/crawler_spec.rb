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

require_relative 'spec_helper'
require 'yavdb/constants'
require 'yavdb/crawler'
require 'yavdb/database'

RSpec.describe YAVDB do
  describe 'Crawler' do
    context 'when we crawl' do
      vulns         = YAVDB::Crawler.vulnerabilities
      grouped_vulns = YAVDB::Database.send(:group_by_package_manager, vulns)

      grouped_vulns.map do |package_manager, vunerabilities_by_pm|
        all_vulnerabilities = vunerabilities_by_pm.map do |package_name, vunerabilities_by_p|
          it "#{package_manager}:#{package_name} should have have vulnerabilities" do
            expect(vunerabilities_by_p).not_to be_empty
          end

          vunerabilities_by_p
        end.flatten

        it "all #{package_manager} package vulnerabilities should have a title" do
          expect(all_vulnerabilities.all? { |vuln| !vuln.title.empty? }).to be true
        end

        it "all #{package_manager} package vulnerabilities should have a valid package manager" do
          expect(all_vulnerabilities.all? { |vuln| YAVDB::Constants::POSSIBLE_PACKAGE_MANAGERS.include?(vuln.package_manager) }).to be true
        end

        it "all #{package_manager} package vulnerabilities severity should be valid" do
          expect(all_vulnerabilities.all? { |vuln| vuln.severity.nil? || YAVDB::Constants::SEVERITIES.include?(vuln.severity) }).to be true
        end

        it "all #{package_manager} package vulnerabilities should have one type of version" do
          expect(
            all_vulnerabilities.all? do |vuln|
              res = (vuln.vulnerable_versions && vuln.vulnerable_versions.any?) ||
                (vuln.unaffected_versions && vuln.unaffected_versions.any?) ||
                (vuln.patched_versions && vuln.patched_versions.any?)

              unless res
                puts ''
                puts 'Fail!'
                puts vuln.id
                puts vuln.title
                puts vuln.package_manager
                puts vuln.affected_package
                puts vuln.source_url
                puts vuln.references
                puts vuln.credit
                puts vuln.credit
                puts vuln
                puts ''
              end

              res
            end
          ).to be true
        end
      end
    end
  end
end
