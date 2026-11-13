package org.safesweep.safesweep;

import android.content.Context;

import androidx.work.Worker;
import androidx.work.WorkerParameters;

/** Runs every few hours (and again after a reboot) to make sure the daily alarm is set. */
public class RearmWorker extends Worker {
    public RearmWorker(Context context, WorkerParameters params) {
        super(context, params);
    }

    @Override
    public Result doWork() {
        DailyCheck.arm(getApplicationContext());
        return Result.success();
    }
}
