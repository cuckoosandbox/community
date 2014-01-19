# Copyright (C) 2014 Robby Zeitfuchs (@robbyFux)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class SectionsEntropy(Signature):
    name = "sections_entropy"
    description = "Is a high likelihood that the file is encrypted or contains compressed data."
    severity = 3
    categories = ["packer"]
    authors = ["Robby Zeitfuchs", "@robbyFux"]
    minimum = "0.6"
    references = ["http://www.forensickb.com/2013/03/file-entropy-explained.html", 
                  "http://virii.es/U/Using%20Entropy%20Analysis%20to%20Find%20Encrypted%20and%20Packed%20Malware.pdf"]

    def run(self):
        hasSignificantAmountOfCompressedData = False
        
        if "static" in self.results:
            if "pe_sections" in self.results["static"]:
                totalCompressedData = 0
                totalPEDataLength = 0
                
                for section in self.results["static"]["pe_sections"]:
                    totalPEDataLength += int(section["size_of_data"], 16)
                     
                    if section["entropy"] > 6.8:
                        self.data.append({"section" : section})
                        totalCompressedData += int(section["size_of_data"], 16)
                
                if ((1.0 * totalCompressedData)/totalPEDataLength) > .2:
                    hasSignificantAmountOfCompressedData = True

        return hasSignificantAmountOfCompressedData
