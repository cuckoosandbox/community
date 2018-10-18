from cuckoo.common.abstracts import Extractor

from roach import Structure, uint8, uint32, rsa, procmem

class KrakenCryptorConfig(Extractor):
    yara_rules = "kraken_cryptor_config"
    minimum = "2.0.5"

    def handle_yara(self, filepath, match):
        # Handle project section
        sproject = match.strings("project")[0]
        for l in sproject.split(","):
            if "version" in l:
                self.version = l.split(":")[1].strip(",")

        # Handle module section
        smodule = match.strings("module")[0]
        

        # Handle core section 
        self.pubkey = match.strings("publickey")[0].split(":")[1].strip('",')

        self.emails = [match.strings("supportemail1")[0].split(":")[1].strip('",'), match.strings("supportemail2")[0].split(":")[1].strip('",')]

        sprice = match.strings("price")[0].split(":")[1].strip('",')
        spriceunit = match.strings("priceunit")[0].split(":")[1].strip('",')
        self.price = sprice + " " + spriceunit
        
        self.extension = match.strings("extension")[0].split(":")[1].strip('",')

        self.helpfile = match.strings("help_name")[1].split(":")[1].strip('",') + "." + match.strings("help_extension")[0].split(":")[1].strip('",')
        
        self.push_config({
            "family": "Kraken Cryptor",
            "pubkey": self.pubkey,
            "url": self.emails,
            "type": "Ransom price: " + self.price + "\nRansom note: " + self.helpfile,
            "ransom_text": self.helpfile
        }) 
