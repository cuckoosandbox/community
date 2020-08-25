rule kraken_cryptor_config
{
    meta:
        author = "brae"
        description  = "Kraken Cryptor configuration identified"

    strings:
        $project = /\"project\"\:\{[^\}]*\}/
        $module = /\"module\"\:\{[^\}]*\}/
        // $core = /\"core\"\:\{[^\}]*\}/
        $core = /\"core\"\:\{/
        $publickey = /\"public_key\"\:\"[^\"]*\"/
        $supportemail1 = /\"support_email_1\"\:\"[^\"]*\"/
        $supportemail2 = /\"support_email_2\"\:\"[^\"]*\"/
        $price = /\"price\"\:[^\,]*/
        $priceunit = /\"price_unit\"\:\"[^\"]*\"/
        $extension = /\"new_extension\"\:\"[^\"]*\"/
        $help_name = /\"name\"\:\"[^\"]*\"/
        $help_extension = /\"extension\"\:\"[^\"]*\"/

    condition:
        // all of ($project, $module, $core)
        3 of them
}
