def detect(sig, results):
    result = False

    for process in results[u"behavior"][u"processes"]:
        for call in process[u"calls"]:
            if any(api in call[u"api"] or call[u"api"] in api for api in sig.apis):
                sig.data.append({u"process": process[u"process_id"], u"call": call})
                result = True

    return result

