package io.github.yunyizea.xsofprivacy;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;

/** Read-only IPC for injected processes. No log contents or write operations are exposed. */
public final class LoggingSettingsProvider extends ContentProvider {
    @Override public boolean onCreate() { return true; }

    @Override public Bundle call(String method, String arg, Bundle extras) {
        if (!LoggingSettings.READ.equals(method))
            throw new IllegalArgumentException("Unsupported settings operation");
        Bundle reply = new Bundle();
        reply.putBoolean(LoggingSettings.ENABLED, LoggingSettings.readLocal(getContext()));
        return reply;
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
                                  String[] args, String order) {
        throw new UnsupportedOperationException("Use the read-only settings call");
    }
    @Override public String getType(Uri uri) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("Read-only settings");
    }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) {
        throw new UnsupportedOperationException("Read-only settings");
    }
    @Override public int delete(Uri uri, String selection, String[] args) {
        throw new UnsupportedOperationException("Read-only settings");
    }
}
