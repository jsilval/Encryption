package com.wimobile.efecty.core.keystore;

import android.os.Build;

public final class SystemServices {

    public static boolean hasMarshmallow() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
    }
}
