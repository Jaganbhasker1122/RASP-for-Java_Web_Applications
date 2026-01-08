function loadExample1() {
    document.getElementById("payloadInput").value = "' OR 1=1 --";
}

function loadExample2() {
    document.getElementById("payloadInput").value = "<script>alert(1)</script>";
}

function analyze() {
    const payload = document.getElementById("payloadInput").value;

    // NORMAL BROWSER NAVIGATION (forces HTML response)
    window.location.href =
        "/lab/sql?input=" + encodeURIComponent(payload);
}
