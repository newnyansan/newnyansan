package org.safesweep.safesweep;

import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;

import java.util.Calendar;
import java.util.concurrent.TimeUnit;

import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;

/**
 * Schedules SafeSweep's automatic daily threat check.
 *
 * - An exact daily alarm starts the check service (exact alarms are one of the few things
 *   Android 12+ allows to start background work).
 * - A WorkManager job re-arms the alarm every few hours; WorkManager survives reboots,
 *   so the schedule comes back after the phone restarts.
 * - If a run was missed (phone off), the check runs ~10 minutes after the alarm is re-armed.
 */
public class DailyCheck {
    static final String PREFS = "safesweep_auto";
    static final int ALARM_REQUEST = 4711;
    static final int RESULT_NOTIFICATION = 4712;
    static final String CHANNEL = "safesweep_results";
    static final long HOUR = 3600L * 1000L;

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public static void enable(Context ctx, int hour, int minute) {
        prefs(ctx).edit().putBoolean("enabled", true).putInt("hour", hour).putInt("minute", minute).apply();
        arm(ctx);
        PeriodicWorkRequest req = new PeriodicWorkRequest.Builder(RearmWorker.class, 6, TimeUnit.HOURS).build();
        WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(
                "safesweep-rearm", ExistingPeriodicWorkPolicy.UPDATE, req);
    }

    public static void disable(Context ctx) {
        prefs(ctx).edit().putBoolean("enabled", false).putLong("next_run", 0).apply();
        AlarmManager am = (AlarmManager) ctx.getSystemService(Context.ALARM_SERVICE);
        am.cancel(pendingIntent(ctx));
        WorkManager.getInstance(ctx).cancelUniqueWork("safesweep-rearm");
    }

    public static boolean isEnabled(Context ctx) {
        return prefs(ctx).getBoolean("enabled", false);
    }

    public static long getNextRun(Context ctx) {
        return prefs(ctx).getLong("next_run", 0);
    }

    public static long getLastRun(Context ctx) {
        return prefs(ctx).getLong("last_run", 0);
    }

    public static void markRun(Context ctx) {
        prefs(ctx).edit().putLong("last_run", System.currentTimeMillis()).apply();
    }

    static PendingIntent pendingIntent(Context ctx) {
        Intent intent = ServiceCheck.getDefaultIntent(ctx, "", "SafeSweep", "Checking for threats", "auto");
        int flags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE;
        if (Build.VERSION.SDK_INT >= 26) {
            return PendingIntent.getForegroundService(ctx, ALARM_REQUEST, intent, flags);
        }
        return PendingIntent.getService(ctx, ALARM_REQUEST, intent, flags);
    }

    public static long nextRunMillis(Context ctx) {
        SharedPreferences p = prefs(ctx);
        long now = System.currentTimeMillis();
        long last = p.getLong("last_run", 0);
        if (last > 0 && now - last > 30 * HOUR) {
            return now + 10 * 60 * 1000L;  // missed a day (phone was off): catch up soon
        }
        Calendar c = Calendar.getInstance();
        c.set(Calendar.HOUR_OF_DAY, p.getInt("hour", 12));
        c.set(Calendar.MINUTE, p.getInt("minute", 30));
        c.set(Calendar.SECOND, 0);
        c.set(Calendar.MILLISECOND, 0);
        if (c.getTimeInMillis() <= now || (last > 0 && c.getTimeInMillis() - last < 20 * HOUR)) {
            c.add(Calendar.DAY_OF_YEAR, 1);
        }
        return c.getTimeInMillis();
    }

    public static void arm(Context ctx) {
        armAt(ctx, nextRunMillis(ctx));
    }

    /** Run the background check in a few seconds (used by "Check now in background" and tests). */
    public static void runSoon(Context ctx, int seconds) {
        armAt(ctx, System.currentTimeMillis() + seconds * 1000L);
    }

    static void armAt(Context ctx, long when) {
        if (!isEnabled(ctx)) {
            return;
        }
        AlarmManager am = (AlarmManager) ctx.getSystemService(Context.ALARM_SERVICE);
        PendingIntent pi = pendingIntent(ctx);
        boolean exact = Build.VERSION.SDK_INT < 31 || am.canScheduleExactAlarms();
        if (exact) {
            am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, when, pi);
        } else {
            am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, when, pi);
        }
        prefs(ctx).edit().putLong("next_run", when).apply();
    }

    public static void notifyResult(Context ctx, String title, String text) {
        NotificationManager nm = (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(new NotificationChannel(
                    CHANNEL, "Threat check results", NotificationManager.IMPORTANCE_DEFAULT));
        }
        Intent open = ctx.getPackageManager().getLaunchIntentForPackage(ctx.getPackageName());
        PendingIntent tap = PendingIntent.getActivity(ctx, 1, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder b = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(ctx, CHANNEL) : new Notification.Builder(ctx);
        b.setContentTitle(title)
         .setContentText(text)
         .setStyle(new Notification.BigTextStyle().bigText(text))
         .setSmallIcon(ctx.getApplicationInfo().icon)
         .setContentIntent(tap)
         .setAutoCancel(true);
        nm.notify(RESULT_NOTIFICATION, b.build());
    }
}
