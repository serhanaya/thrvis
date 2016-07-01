# thrvis
Visual Analysis of Cyber Threat

In the Part 1: Acquiring the Data, the virus data is obtained from Avira web site using rvest package. The obtained data cleaned for further investigation in Part 2: Cleaning the Data. At the last part, Part 3: Exploratory Analysis, the data is explored using various visualization approaches. In the process, lubridate package is used for date type. For string manipulation, stringr package is used. tidyr, plyr and dplyr packages are used for data wrangling. ggplot package is used for the most of the visualizations.

The data consist of properties of viruses such as their names (with their prefix and suffix for variations), their impact, influence, documentation date, information date, discovery date as well as their target operating system. The time interval for this data is approximately 8 months. Various questions are asked/answered in the Part 3: Exploratory Analysis. The visualizations are mostly focused on the variables change over time. Besides, a heatmap for comparison of the properties of the most frequent viruses also provided in this section.
