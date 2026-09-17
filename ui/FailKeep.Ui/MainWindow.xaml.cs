using FailKeep.Ui.Pages;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;

namespace FailKeep.Ui;

public sealed partial class MainWindow : Microsoft.UI.Xaml.Window
{
    public MainWindow()
    {
        InitializeComponent();
        ExtendsContentIntoTitleBar = true;
        ContentFrame.Navigate(typeof(OverviewPage), null, new SuppressNavigationTransitionInfo());
        Nav.SelectedItem = Nav.MenuItems[0];
    }

    private void Nav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is NavigationViewItem item && item.Tag is string tag)
        {
            var page = tag switch
            {
                "overview" => typeof(OverviewPage),
                "lists" => typeof(ListsPage),
                "jails" => typeof(JailsPage),
                "settings" => typeof(SettingsPage),
                _ => typeof(OverviewPage)
            };
            ContentFrame.Navigate(page, null, new SuppressNavigationTransitionInfo());
        }
    }
}
