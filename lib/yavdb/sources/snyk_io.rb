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

require 'oga'
require 'oga/xml/entities'
require 'kramdown'

require_relative '../dtos/advisory'
require_relative '../utils/http'

module YAVDB
  module Sources
    module SnykIO
      class Client

        BASE_URL      = 'https://snyk.io'
        BASE_VULN_URL = "#{BASE_URL}/vuln"
        INFO_SEP      = '#=#'

        PACKAGE_MANAGERS_RSS_FEED = ['composer', 'golang', 'maven', 'npm', 'nuget', 'pip', 'rubygems'].freeze

        PACKAGE_MANAGER_ALIAS = Hash[
          'composer' => 'packagist',
          'go'       => 'go',
          'maven'    => 'maven',
          'npm'      => 'npm',
          'nuget'    => 'nuget',
          'pip'      => 'pypi',
          'rubygems' => 'rubygems'
        ].freeze

        def self.advisories
          urls = fetch_advisory_urls
          urls.map do |advisory_url|
            advisory_page = get_page_html(advisory_url, true, 'snyk.io/advisories')
            create(advisory_url, advisory_page)
          end
        end

        class << self

          private

          def fetch_advisory_urls
            PACKAGE_MANAGERS_RSS_FEED.map do |pm|
              fetch_advisory_recursive("#{BASE_VULN_URL}?type=#{pm}")
            end.flatten
          end

          def fetch_advisory_recursive(page_url)
            snykio = get_page_html(page_url, true, 'snyk.io/feed')

            page_vuln_urls = snykio
                               .css('table tbody tr td span a')
                               .map { |anchor| anchor.get('href') }
                               .map { |link| link if link =~ %r{\/vuln\/.+} }.compact

            next_urls = if page_vuln_urls.any?
                          next_url = snykio.css('a.pagination__next')
                          if next_url
                            fetch_advisory_recursive(next_url.first.get('href'))
                          else
                            []
                          end
                        else
                          []
                        end

            page_vuln_urls
              .concat(next_urls)
              .map do |url|
              full_url = url
              full_url = "#{BASE_URL}#{url}" unless url.start_with?('http')
              full_url
            end
          end

          def create(advisory_url, advisory_page)
            severity = advisory_page.css('span.label__text').text.gsub(%r{(.*?) severity}, '\1')

            package_manager = advisory_page.css('.breadcrumbs__list-item')[1].text.gsub(%r{\s+}, '').downcase
            package_manager = PACKAGE_MANAGER_ALIAS[package_manager] || raise("Could not find alias for package manager #{package_manager}")

            title = utf8(advisory_page.css('h1.header__title span.header__title__text').text)

            affected_package = advisory_page.css('.custom-package-name').text
            affected_package = advisory_page.css('.header__lede .breadcrumbs__list-item__link').text if affected_package.empty?

            vulnerable_versions = advisory_page.css('.custom-affected-versions').text.strip
            vulnerable_versions = if vulnerable_versions.empty? || vulnerable_versions == 'ALL'
                                    ['*']
                                  else
                                    [vulnerable_versions]
                                  end

            sidebar_data = parse_side_bar(advisory_page)
            body_data    = parse_body(advisory_page)

            published_date     = parse_date(sidebar_data[:published_date].to_s)
            disclosed_date     = parse_date(sidebar_data[:disclosed_date].to_s) || published_date
            last_modified_date = if sidebar_data[:last_modified_date]
                                   parse_date(sidebar_data[:last_modified_date].to_s)
                                 else
                                   published_date
                                 end

            YAVDB::Advisory.new(
              "snykio:#{package_manager}:#{affected_package}:#{disclosed_date}",
              title,
              body_data[:description],
              affected_package,
              vulnerable_versions,
              nil, #:unaffected_versions
              nil, #:patched_versions
              severity,
              package_manager,
              sidebar_data[:cve],
              sidebar_data[:cwe],
              nil, #:osvdb
              nil, #:cvss_v2_vector
              nil, #:cvss_v2_score
              nil, #:cvss_v3_vector
              nil, #:cvss_v3_score
              disclosed_date,
              published_date,
              last_modified_date,
              [sidebar_data[:credit]].flatten,
              body_data[:references],
              advisory_url
            )
          end

          def parse_body(advisory_page)
            data = {}

            description_sections = []
            overview_fields      = advisory_page.css('.card.card--markdown .card__content > *')
            overview_fields.each do |field|
              if field.name == 'h2'
                description_sections.push(:header => field, :body => [])
              elsif description_sections.any?
                last_elem        = description_sections.last
                new_body         = last_elem[:body].push(field)
                last_elem[:body] = new_body
                description_sections.push(last_elem)
              end
            end

            description_sections.map do |section|
              header = section[:header]
              body   = section[:body]

              case header.text
                when 'Overview' then
                  overview_str = body
                                   .map(&:to_xml)
                                   .join("\n")
                                   .force_encoding('UTF-8')
                  begin
                    data[:description] += '\n' if data[:description]
                    data[:description] = '' unless data[:description]
                    data[:description] += utf8(Kramdown::Document.new(overview_str, :html_to_native => true).to_kramdown)
                  rescue StandardError
                    # ignore
                  end
                when 'Details' then
                  details_str = body
                                  .map(&:to_xml)
                                  .join("\n")
                                  .force_encoding('UTF-8')
                  begin
                    data[:description] += '\n' if data[:description]
                    data[:description] = '' unless data[:description]
                    data[:description] += utf8(Kramdown::Document.new(details_str, :html_to_native => true).to_kramdown)
                  rescue StandardError
                    # ignore
                  end
                when 'References' then
                  references = []
                  if body.any?
                    body.first.css('li a').map do |elem|
                      references.push(elem.get('href'))
                    end
                  end
                  data[:references] = references.flatten
              end
            end

            data
          end

          def parse_side_bar(advisory_page)
            data = {}

            advisory_page.css('.l-col .card .card__content dl > *').each_slice(2).to_a.map do |key, value|
              case key.text
                when 'Credit' then
                  data[:credit] = utf8(value.text.split(',').map { |str| str.strip.sub(%r{-\s*}, '') }.reject(&:empty?))
                when 'CVE' then
                  data[:cve] = value.css('a').map { |a| a.text.strip.split(',') }.flatten.map(&:strip).reject(&:empty?)
                when 'CWE' then
                  data[:cwe] = value.css('a').map { |a| a.text.strip.split(',') }.flatten.map(&:strip).reject(&:empty?)
                when 'Snyk ID' then
                  data[:id] = value.text.strip
                when 'Disclosed' then
                  data[:disclosed_date] = value.text.strip
                when 'Published' then
                  data[:published_date] = value.text.strip
                when 'Last modified' then
                  data[:last_modified_date] = value.text.strip
              end
            end

            data
          end

          def get_page_html(source_url, with_cache, group_cache_key)
            source_url = "#{BASE_URL}#{source_url}" unless source_url.start_with?('http')
            body_lines = YAVDB::Utils::HTTP.get_page_contents(source_url, with_cache, group_cache_key)
            body_lines = escape_vulnerable_versions(body_lines)
            Oga.parse_html(body_lines, :strict => true)
          end

          def clean_references(references)
            references.map do |reference|
              reference
                .gsub(%r{\s*-\s*(.*)}, '\1')
                .gsub(%r{\[.+?\]\((.*)\).*}, '\1')
                .strip
            end
          end

          def parse_date(date_str)
            Date.strptime(date_str, '%d %b, %Y')
          rescue ArgumentError
            # ignore
          end

          # HACK: Page contains non UTF-8 characters and we need to fix it to be able to convert to json
          def utf8(value)
            if value.is_a?(Array)
              value.map { |sub_value| utf8(sub_value) }
            elsif value.is_a?(String)
              value.force_encoding('UTF-8')
            else
              value
            end
          end

          # HACK: Page contains invalid HTML and we need to fix it to get the affected version
          def escape_vulnerable_versions(body_lines)
            cleaning = false
            body_lines.map do |line|
              if line.include?('<h2 id="overview">Overview</h2>')
                cleaning = true
              elsif line.include?('<h2 id=')
                cleaning = false
              end

              if cleaning
                key  = '<script>'
                line = line.gsub(key, Oga::XML::Entities.encode(key))
              end

              if line.include?(', versions')
                extracted     = line.gsub(%r{\s*<strong\s*>(.*)<\/strong>\s*}, '\1')
                                  .gsub(%r{\s*<a.*>(.*)<\/a><\/strong>\s*}, '\1 ')
                                  .gsub(%r{\s*<\/p>\s*}, '')
                                  .gsub(%r{\s*<\/strong>\s*}, ' ')
                                  .gsub(%r{\s*(.*)\s*}, '\1')
                                  .gsub(%r{(\S*)(?:\s+.*)?,\s*versions\s*(.*)\s*}, "\\1#{INFO_SEP}\\2")
                                  .tr("\n", ' ')
                                  .gsub('&nbsp;', ' ')
                                  .split(INFO_SEP)
                fixed_version = Oga::XML::Entities.encode(extracted[1])
                "</strong><span class=\"custom-package-name\">#{extracted[0]}</span><span class=\"custom-affected-versions\">#{fixed_version}</span>"
              elsif line.include?(', <strong >ALL</strong> versions')
                extracted = line.gsub(%r{\s*<strong\s*>(.*)<\/strong>\s*}, '\1')
                              .gsub(%r{\s*<a.*>(.*)<\/a><\/strong>\s*}, '\1 ')
                              .gsub(%r{\s*<\/p>\s*}, '')
                              .gsub(%r{\s*<\/strong>\s*}, ' ')
                              .gsub(%r{\s*(.*)\s*}, '\1')
                              .gsub(%r{(\S*)(?:\s+.*)?,\s*.*\s*versions\s*}, '\1')
                              .tr("\n", ' ')
                              .split(INFO_SEP)
                "</strong><span class=\"custom-package-name\">#{extracted[0]}</span><span class=\"custom-affected-versions\">*</span>"
              else
                line
              end
            end
          end

        end

      end
    end
  end
end
