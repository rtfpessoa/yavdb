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

require 'English'

require_relative '../constants'

module YAVDB
  module Utils
    module Executor

      def self.run(cmd)
        puts "[Running] #{cmd}" if Constants::DEBUG
        output = `#{cmd}`
        {
          :output   => output,
          :success? => $CHILD_STATUS.success?
        }
      end

    end
  end
end
