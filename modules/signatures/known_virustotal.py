from lib.cuckoo.common.abstracts import Signature

class KnownVirustotal(Signature):
    name = "known_virustotal"
    description = "File has been identified by AV on virustotal as malicious"
    severity = 3
    categories = ["generic"]
    authors = ["Michael Boman"]

    def run(self, results):
        try:
            results["virustotal"]
            #if results["virustotal"]["positives"] != None:
            #    print "results['virustotal']['positives'] = " + str(results["virustotal"]["positives"])
            #    print "results['virustotal']['total'] = " + str(results["virustotal"]["total"])
            #    percent_f = (float(results["virustotal"]["positives"]) / float(results["virustotal"]["total"])) * 100.0
            #    percent_i = int(percent_f)
            #    print "Detection rate: " + str(percent_f) + "%"
            #    print "Detection rate: " + str(percent_i) + "%"
        except NameError:
            return False
        else:
            percent_f = (float(results["virustotal"]["positives"]) / float(results["virustotal"]["total"])) * 100.0
            percent_i = int(percent_f)
            if results["virustotal"]["positives"] > 0:
                self.data.append({"virus_total" : results["virustotal"]})
                return True

        return False
