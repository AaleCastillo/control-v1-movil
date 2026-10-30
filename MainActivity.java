package com.miremoto.tv;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
  @Override
  public void onCreate(Bundle b) {
    registerPlugin(TvRemotePlugin.class);
    super.onCreate(b);
  }
}
