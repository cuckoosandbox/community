rule OfficeDDE {
    strings:
        $s1 = "w:instrText"

    condition:
      filename matches /word\/document.xml/ and $s1
}
