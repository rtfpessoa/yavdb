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

require_relative 'constants'
require_relative 'utils/semver'

module YAVDB
  class Database

    def self.save(database_path, vulns)
      vulns_grouped_by_package_manager = group_by_package_manager(vulns)
      save_to_file(database_path, vulns_grouped_by_package_manager)
    end

    def self.search(database_path, package_manager, package_name)
      package_file_path = package_path(database_path, package_manager, package_name)

      if File.exist?(package_file_path)
        YAVDB::Advisory.load(package_file_path)
      else
        []
      end
    end

    class << self

      private

      def group_by_package_manager(vulns)
        vulns
          .group_by(&:package_manager)
          .map do |package_manager, vunerabilities_by_pm|

          puts "#{package_manager}: #{vunerabilities_by_pm.length}"

          vunerabilities_by_pm =
            vunerabilities_by_pm
              .group_by(&:affected_package)
              .map do |package, vunerabilities_by_p|
              [package, vunerabilities_by_p]
            end.to_h

          [package_manager, vunerabilities_by_pm]
        end.to_h
      end

      def save_to_file(database_path, vulns)
        vulns.map do |package_manager, vunerabilities_by_pm|
          vunerabilities_by_pm.map do |package, vunerabilities_by_p|
            previous_vulnerabilities = search(database_path, package_manager, package)

            package_path           = package_path(database_path, package_manager, package)
            package_path_directory = File.dirname(package_path)
            FileUtils.mkdir_p(package_path_directory) unless File.exist?(package_path_directory)

            uniq_vunerabilities_by_p = Hash[previous_vulnerabilities.concat(vunerabilities_by_p).map { |vuln| [vuln.id, vuln] }].values

            next unless uniq_vunerabilities_by_p.any?

            File.open(package_path, 'wb') do |file|
              package_vulns_yml_str = uniq_vunerabilities_by_p
                                        .sort_by(&:id)
                                        .map(&:to_map)
                                        .to_yaml(
                                          :Indent => 4,
                                          :SortKeys => true,
                                          :UseHeader => true,
                                          :UseVersion => true,
                                          :ExplicitTypes => true,
                                          :BestWidth => 80,
                                          :UseFold => true,
                                          :UseBlock => true,
                                          :Encoding => :Utf8
                                        )

              file.puts(package_vulns_yml_str)
            end
          end
        end
      end

      def package_path(database_path, package_manager, package_name)
        File.expand_path(File.join(database_path, package_manager, "#{package_name}.yml"))
      end

    end

  end
end
