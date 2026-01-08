package com.rasplab.rasplab.detection;

import com.rasplab.rasplab.context.HttpRequestContext;

public interface RaspDetector {
    DetectionResult analyze(HttpRequestContext ctx);
}
