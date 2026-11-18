using System;
using System.Collections.Generic;
using System.Globalization;
using System.Windows;

namespace ClaudeSafe.Localization;

/// <summary>
/// Runtime localization manager supporting zh-CN, en-US, and OS auto-detection.
/// Syncs an active ResourceDictionary into Application.Current.Resources for instant XAML DynamicResource updates.
/// </summary>
public static class L
{
    public const string Auto = "auto";
    public const string ZhCN = "zh-CN";
    public const string EnUS = "en-US";

    private static readonly object SyncLock = new();
    private static ResourceDictionary? _activeResourceDictionary;
    private static IReadOnlyDictionary<string, string> _activeMap = StringsZhCN.Map;

    public static string SelectedSetting { get; private set; } = Auto;
    public static string CurrentLanguage { get; private set; } = ZhCN;
    public static bool IsEnglish => string.Equals(CurrentLanguage, EnUS, StringComparison.OrdinalIgnoreCase);

    public static event Action? LanguageChanged;

    static L()
    {
        ApplyLanguageInternal(Auto, notify: false);
    }

    public static string NormalizeSetting(string? setting)
    {
        if (string.IsNullOrWhiteSpace(setting))
            return Auto;

        var trimmed = setting.Trim();
        if (trimmed.Equals(ZhCN, StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("zh", StringComparison.OrdinalIgnoreCase))
            return ZhCN;

        if (trimmed.Equals(EnUS, StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("en", StringComparison.OrdinalIgnoreCase))
            return EnUS;

        return Auto;
    }

    public static string ResolveLanguage(string? setting)
    {
        var normalized = NormalizeSetting(setting);
        if (normalized == ZhCN) return ZhCN;
        if (normalized == EnUS) return EnUS;

        var uiCulture = CultureInfo.CurrentUICulture.Name;
        return uiCulture.StartsWith("zh", StringComparison.OrdinalIgnoreCase) ? ZhCN : EnUS;
    }

    public static void SetLanguage(string? setting, bool notify = true)
    {
        ApplyLanguageInternal(setting, notify);
    }

    public static string Get(string key)
    {
        if (string.IsNullOrEmpty(key))
            return string.Empty;

        var map = _activeMap;
        if (map.TryGetValue(key, out var value))
            return value;

        if (StringsZhCN.Map.TryGetValue(key, out var fallback))
            return fallback;

        return key;
    }

    public static string Format(string key, params object?[] args)
    {
        var template = Get(key);
        return string.Format(CultureInfo.CurrentCulture, template, args);
    }

    public static (bool IsValid, List<string> MissingInEn, List<string> MissingInZh) ValidateDictionaries()
    {
        var missingInEn = new List<string>();
        var missingInZh = new List<string>();

        foreach (var key in StringsZhCN.Map.Keys)
        {
            if (!StringsEnUS.Map.ContainsKey(key))
                missingInEn.Add(key);
        }

        foreach (var key in StringsEnUS.Map.Keys)
        {
            if (!StringsZhCN.Map.ContainsKey(key))
                missingInZh.Add(key);
        }

        return (missingInEn.Count == 0 && missingInZh.Count == 0, missingInEn, missingInZh);
    }

    private static void ApplyLanguageInternal(string? setting, bool notify)
    {
        lock (SyncLock)
        {
            SelectedSetting = NormalizeSetting(setting);
            CurrentLanguage = ResolveLanguage(SelectedSetting);
            _activeMap = CurrentLanguage == EnUS ? StringsEnUS.Map : StringsZhCN.Map;

            var app = Application.Current;
            if (app != null)
            {
                void UpdateResources()
                {
                    var dict = new ResourceDictionary();
                    foreach (var kvp in _activeMap)
                    {
                        dict[kvp.Key] = kvp.Value;
                    }

                    var merged = app.Resources.MergedDictionaries;
                    if (_activeResourceDictionary != null)
                    {
                        merged.Remove(_activeResourceDictionary);
                    }
                    merged.Add(dict);
                    _activeResourceDictionary = dict;
                }

                if (app.Dispatcher.CheckAccess())
                {
                    UpdateResources();
                }
                else
                {
                    app.Dispatcher.BeginInvoke(UpdateResources);
                }
            }
        }

        if (notify)
        {
            LanguageChanged?.Invoke();
        }
    }
}
