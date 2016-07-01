# Visual Analysis of Cyber Threat. Part 3_c: Exploratory Analysis - Time-Series Calendar Heatmap
# Serhan Aya 2016-07-02.

# This is a subsection for Part 3: Exploratory Analysis. The time-series calendar
# heatmap is a beautiful visualization for the variables changing over time. Here,
# the question is: "How frequent is a specific virus seen?". See the example
# at the end of the script.

# Load required packages.
library(feather)    # Save/load the dataframe
library(lubridate)  # Date manipulation
library(plyr)       # Data manipulation
library(dplyr)      # Data manipulation
library(zoo)        # Date manipulation
library(ggplot2)    # Visualization

# Load dataframe
df <- read_feather("data/tVDClean.feather")

# `plt_ts_heatmap` function takes a dataframe and a virusname
# and plots the time-series calendar heatmap. The details are
# explained within the function.
plt_ts_heatmap <- function(df, virName) {

    # Make a new dataframe.
    temp <- df %>%
        filter(NName == virName) %>%
        na.omit() %>%
        group_by(DateDiscovered) %>%
        summarise(Count = n()) %>%
        select(DateDiscovered, Count)

    # Facet by year ~ month, (each subgraph will
    # show week-of-month versus weekday)
    # The year
    temp$year<-year(temp$DateDiscovered)

    # The month
    temp$month<-month(temp$DateDiscovered)

    # Turn months into ordered facors to control the
    # appearance/ordering in the presentation
    temp$monthf<-factor(temp$month,levels=as.character(1:12),
        labels=c("Jan","Feb","Mar","Apr","May","Jun","Jul",
        "Aug","Sep","Oct","Nov","Dec"), ordered=TRUE)

    # The day of week
    temp$weekday = wday(temp$DateDiscovered)

    # Turn into factors to control appearance/abbreviation and ordering
    # Reverse function rev used here to order the week top down in the graph
    temp$weekdayf<-factor(temp$weekday,levels=rev(1:7),
        labels=rev(c("Mon","Tue","Wed","Thu","Fri","Sat","Sun")),
        ordered=TRUE)

    # Cut the data into month chunks
    temp$yearmonth<-as.yearmon(temp$DateDiscovered)
    temp$yearmonthf<-factor(temp$yearmonth)

    # Find the "week of year" for each day,
    temp$week <- week(temp$DateDiscovered)

    # For each monthblock, normalize the week to start at 1
    temp<-ddply(temp,.(yearmonthf),transform,monthweek=1+week-min(week))

    # Plot
    P <- ggplot(temp, aes(monthweek, weekdayf, fill = Count)) +
        geom_tile(colour = "white") + facet_grid(year~monthf) +
        scale_fill_gradient(low="lightblue", high="darkblue") +
        labs(title = paste("Time-Series Calendar Heatmap for", virName),
             x="Week of the Month", y=NULL)
    P
}
# Plot the heatmap for `Elex` virus.
plt_ts_heatmap(df, "Agent")
